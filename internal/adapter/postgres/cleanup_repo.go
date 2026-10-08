package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/secretli/server/internal/adapter/postgres/dbsqlc"
	"github.com/secretli/server/internal/domain"
)

// The cleanup's sweeps. All but DeleteDoomedObjects are database work only:
// they end things and doom objects, and DeleteDoomedObjects is the one place
// that deletes from storage.

func (r *SecretRepo) DeleteExpiredRetrievalSessions(ctx context.Context, now time.Time) (int64, error) {
	n, err := r.q.DeleteExpiredRetrievalSessions(ctx, timestamptz(now))
	if err != nil {
		return 0, fmt.Errorf("delete expired retrieval sessions: %w", err)
	}
	return n, nil
}

// AbandonExpiredUploads abandons one batch of at most limit uploads that ran
// out of time, oldest first, and returns how many it abandoned.
func (r *SecretRepo) AbandonExpiredUploads(ctx context.Context, now time.Time, limit int) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin expired uploads tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	sessionIDs, err := qtx.ListExpiredUploadsForUpdate(ctx, dbsqlc.ListExpiredUploadsForUpdateParams{
		NowAt:     timestamptz(now),
		BatchSize: int32(limit), //nolint:gosec // small constant chosen by the caller
	})
	if err != nil {
		return 0, fmt.Errorf("select expired uploads: %w", err)
	}
	if len(sessionIDs) > 0 {
		if err := abandonUploads(ctx, qtx, sessionIDs, now); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit expired uploads: %w", err)
	}
	return len(sessionIDs), nil
}

// DeleteFinishedUploads forgets uploads that completed or were abandoned
// before the given time.
func (r *SecretRepo) DeleteFinishedUploads(ctx context.Context, finishedBefore time.Time) (int64, error) {
	n, err := r.q.DeleteFinishedUploads(ctx, timestamptz(finishedBefore))
	if err != nil {
		return 0, fmt.Errorf("delete finished uploads: %w", err)
	}
	return n, nil
}

// ReleaseDrainedSecrets dooms the objects of one batch of at most limit
// opened one-time secrets whose last download session has ended, and returns
// how many it released.
func (r *SecretRepo) ReleaseDrainedSecrets(ctx context.Context, now time.Time, limit int) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin drained secrets tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	rows, err := qtx.ListDrainedSecretsForUpdate(ctx, dbsqlc.ListDrainedSecretsForUpdateParams{
		NowAt:     timestamptz(now),
		BatchSize: int32(limit), //nolint:gosec // small constant chosen by the caller
	})
	if err != nil {
		return 0, fmt.Errorf("select drained secrets: %w", err)
	}
	if len(rows) > 0 {
		publicIDs := make([]string, 0, len(rows))
		storageKeys := make([]string, 0, len(rows))
		for _, row := range rows {
			publicIDs = append(publicIDs, row.PublicID)
			storageKeys = append(storageKeys, row.StorageKey.String)
		}
		if err := qtx.ClearStorageKeys(ctx, publicIDs); err != nil {
			return 0, fmt.Errorf("clear drained secrets' storage keys: %w", err)
		}
		if err := qtx.DoomObjects(ctx, dbsqlc.DoomObjectsParams{
			NowAt:       timestamptz(now),
			StorageKeys: storageKeys,
		}); err != nil {
			return 0, fmt.Errorf("doom drained secrets' objects: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit drained secrets: %w", err)
	}
	return len(rows), nil
}

// DeleteExpiredSecrets forgets one batch of at most limit secrets past their
// expiry, oldest first, dooming the objects they still hold, and returns how
// many it deleted. Nothing about a secret outlives its expiry.
func (r *SecretRepo) DeleteExpiredSecrets(ctx context.Context, now time.Time, limit int) (int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin expired secrets tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	rows, err := qtx.ListExpiredSecretsForUpdate(ctx, dbsqlc.ListExpiredSecretsForUpdateParams{
		NowAt:     timestamptz(now),
		BatchSize: int32(limit), //nolint:gosec // small constant chosen by the caller
	})
	if err != nil {
		return 0, fmt.Errorf("select expired secrets: %w", err)
	}
	var deleted int64
	if len(rows) > 0 {
		publicIDs := make([]string, 0, len(rows))
		storageKeys := make([]string, 0, len(rows))
		for _, row := range rows {
			publicIDs = append(publicIDs, row.PublicID)
			if row.StorageKey.Valid {
				storageKeys = append(storageKeys, row.StorageKey.String)
			}
		}
		if err := qtx.DoomObjects(ctx, dbsqlc.DoomObjectsParams{
			NowAt:       timestamptz(now),
			StorageKeys: storageKeys,
		}); err != nil {
			return 0, fmt.Errorf("doom expired secrets' objects: %w", err)
		}
		if deleted, err = qtx.DeleteSecretsByPublicIDs(ctx, publicIDs); err != nil {
			return 0, fmt.Errorf("delete expired secrets: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit expired secrets: %w", err)
	}
	return int(deleted), nil
}

// DeleteDoomedObjects removes one batch of at most limit doomed objects,
// oldest first. remove runs for each row while it is locked and must delete
// the object from storage; rows it fails for are kept for a later cycle.
// Nothing but this sweep locks a doomed object's row, so the storage calls
// hold up no request.
func (r *SecretRepo) DeleteDoomedObjects(ctx context.Context, limit int, remove func(object *domain.Object) error) (domain.CleanupBatch, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.CleanupBatch{}, fmt.Errorf("begin doomed objects tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	rows, err := qtx.ListDoomedObjectsForUpdate(ctx, int32(limit)) //nolint:gosec // small constant chosen by the caller
	if err != nil {
		return domain.CleanupBatch{}, fmt.Errorf("select doomed objects: %w", err)
	}

	// Only rows whose object is gone are deleted, in one statement: a failed
	// statement aborts the whole transaction, so there is no deleting row by
	// row and carrying on after an error.
	removed := make([]string, 0, len(rows))
	for _, row := range rows {
		object := objectFromRow(row)
		if err := remove(object); err != nil {
			slog.ErrorContext(ctx, "cleanup: removing object failed, keeping it", "storage_key", object.StorageKey, "error", err)
			continue
		}
		removed = append(removed, object.StorageKey)
	}

	var deleted int64
	if len(removed) > 0 {
		if deleted, err = qtx.DeleteObjects(ctx, removed); err != nil {
			return domain.CleanupBatch{}, fmt.Errorf("delete doomed objects: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.CleanupBatch{}, fmt.Errorf("commit doomed objects: %w", err)
	}
	return domain.CleanupBatch{Found: len(rows), Removed: int(deleted)}, nil
}

func objectFromRow(row dbsqlc.Object) *domain.Object {
	return &domain.Object{
		StorageKey: row.StorageKey,
		State:      domain.ObjectState(row.State),
		S3UploadID: row.S3UploadID.String,
		CreatedAt:  row.CreatedAt.Time,
		DoomedAt:   pointerFromTimestamp(row.DoomedAt),
	}
}
