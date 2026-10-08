package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/secretli/server/internal/adapter/postgres/dbsqlc"
	"github.com/secretli/server/internal/domain"
)

func (r *SecretRepo) StartUpload(ctx context.Context, secret *domain.Secret, upload *domain.Upload, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin start upload tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	if r.maxStoredBytes > 0 {
		if err := qtx.LockUploadStarts(ctx); err != nil {
			return fmt.Errorf("lock upload starts: %w", err)
		}
		stored, err := qtx.StoredBytes(ctx)
		if err != nil {
			return fmt.Errorf("query stored bytes: %w", err)
		}
		if stored+secret.BlobSize > r.maxStoredBytes {
			return domain.ErrStorageFull
		}
	}

	// The object is known before anything is written under its key.
	if err := qtx.CreateObject(ctx, dbsqlc.CreateObjectParams{
		StorageKey: secret.StorageKey,
		CreatedAt:  timestamptz(now),
	}); err != nil {
		return fmt.Errorf("insert object: %w", err)
	}
	err = qtx.CreateSecret(ctx, dbsqlc.CreateSecretParams{
		PublicID:          secret.PublicID,
		StorageKey:        text(secret.StorageKey),
		MetadataTokenHash: secret.MetadataTokenHash,
		BlobTokenHash:     text(secret.BlobTokenHash),
		DeletionTokenHash: text(secret.DeletionTokenHash),
		EncryptedMeta:     text(secret.EncryptedMeta),
		BlobSize:          secret.BlobSize,
		BurnAfterRead:     secret.BurnAfterRead,
		ExpiresAt:         timestamptz(secret.ExpiresAt),
	})
	if err != nil && isDuplicateKeyError(err) {
		return domain.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("insert secret: %w", err)
	}
	if err := qtx.CreateUpload(ctx, dbsqlc.CreateUploadParams{
		SessionID:       upload.SessionID,
		PublicID:        text(secret.PublicID),
		UploadTokenHash: upload.UploadTokenHash,
		ExpiresAt:       timestamptz(upload.ExpiresAt),
	}); err != nil {
		return fmt.Errorf("insert upload: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit start upload: %w", err)
	}
	return nil
}

func (r *SecretRepo) RecordS3UploadID(ctx context.Context, storageKey, s3UploadID string) error {
	n, err := r.q.RecordS3UploadID(ctx, dbsqlc.RecordS3UploadIDParams{
		S3UploadID: text(s3UploadID),
		StorageKey: storageKey,
	})
	if err != nil {
		return fmt.Errorf("record multipart upload id: %w", err)
	}
	if n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *SecretRepo) GetUpload(ctx context.Context, sessionID string) (*domain.Upload, []domain.UploadPart, error) {
	row, err := r.q.GetUpload(ctx, sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("query upload: %w", err)
	}

	parts, err := r.q.ListUploadParts(ctx, sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("query upload parts: %w", err)
	}
	return uploadFromRow(row), uploadPartsFromRows(parts), nil
}

func (r *SecretRepo) RecordUploadPart(ctx context.Context, part *domain.UploadPart) (*domain.UploadPart, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin upload part tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	existing, err := qtx.GetUploadPartForUpdate(ctx, dbsqlc.GetUploadPartForUpdateParams{
		SessionID:  part.SessionID,
		PartNumber: int32(part.PartNumber), //nolint:gosec // bounded by the handler
	})
	if err == nil {
		existingPart := uploadPartFromRow(existing)
		if existingPart.Offset != part.Offset || existingPart.Size != part.Size || existingPart.SHA256 != part.SHA256 {
			return nil, domain.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit existing upload part: %w", err)
		}
		return existingPart, nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("query upload part: %w", err)
	}

	inserted, err := qtx.CreateUploadPart(ctx, dbsqlc.CreateUploadPartParams{
		SessionID:  part.SessionID,
		PartNumber: int32(part.PartNumber), //nolint:gosec // bounded by the handler
		PartOffset: part.Offset,
		PartSize:   part.Size,
		PartSha256: part.SHA256,
		Etag:       part.ETag,
	})
	if err != nil && isDuplicateKeyError(err) {
		return nil, domain.ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("insert upload part: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit upload part: %w", err)
	}
	return uploadPartFromRow(inserted), nil
}

func (r *SecretRepo) ClearUploadParts(ctx context.Context, sessionID string) error {
	if err := r.q.DeleteUploadParts(ctx, sessionID); err != nil {
		return fmt.Errorf("clear upload parts: %w", err)
	}
	return nil
}

func (r *SecretRepo) CompleteUpload(ctx context.Context, sessionID string, now time.Time, finalize func(*domain.Upload, []domain.UploadPart) error) (*domain.Upload, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin complete upload tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	row, err := qtx.GetUploadForUpdate(ctx, sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query upload for complete: %w", err)
	}
	upload := uploadFromRow(dbsqlc.GetUploadRow(row))
	switch upload.State {
	case domain.UploadCompleted:
		return upload, nil
	case domain.UploadUploading:
	default:
		return nil, domain.ErrConflict
	}

	// Read the parts under the lock: the caller's earlier read may predate a
	// concurrent part upload or reset.
	partRows, err := qtx.ListUploadParts(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query upload parts for complete: %w", err)
	}
	if err := finalize(upload, uploadPartsFromRows(partRows)); err != nil {
		return nil, err
	}

	n, err := qtx.MakeSecretLive(ctx, dbsqlc.MakeSecretLiveParams{
		NowAt:    timestamptz(now),
		PublicID: upload.PublicID,
	})
	if err != nil {
		return nil, fmt.Errorf("make secret live: %w", err)
	}
	if n != 1 {
		return nil, fmt.Errorf("make secret live: secret %q of upload %q is not uploading", upload.PublicID, sessionID)
	}
	if err := qtx.MarkObjectStored(ctx, upload.StorageKey); err != nil {
		return nil, fmt.Errorf("mark object stored: %w", err)
	}
	if err := qtx.MarkUploadCompleted(ctx, dbsqlc.MarkUploadCompletedParams{
		NowAt:     timestamptz(now),
		SessionID: sessionID,
	}); err != nil {
		return nil, fmt.Errorf("mark upload completed: %w", err)
	}
	if err := qtx.DeleteUploadParts(ctx, sessionID); err != nil {
		return nil, fmt.Errorf("delete completed upload parts: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit complete upload: %w", err)
	}

	upload.State = domain.UploadCompleted
	upload.FinishedAt = &now
	return upload, nil
}

func (r *SecretRepo) AbortUpload(ctx context.Context, sessionID string, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin abort upload tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	row, err := qtx.GetUploadForUpdate(ctx, sessionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query upload for abort: %w", err)
	}
	switch domain.UploadState(row.State) {
	case domain.UploadCompleted:
		return domain.ErrConflict
	case domain.UploadAbandoned:
		return nil
	}

	if err := abandonUploads(ctx, qtx, []string{sessionID}, now); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit abort upload: %w", err)
	}
	return nil
}

// abandonUploads ends uploads under way whose rows the caller has locked:
// each is marked abandoned, its secret's row goes, which frees the public id,
// and its object is doomed. The uploads are marked first, because deleting
// the secret clears the upload's public id, which only a finished upload may
// lack.
func abandonUploads(ctx context.Context, qtx *dbsqlc.Queries, sessionIDs []string, now time.Time) error {
	publicIDs, err := qtx.MarkUploadsAbandoned(ctx, dbsqlc.MarkUploadsAbandonedParams{
		NowAt:      timestamptz(now),
		SessionIds: sessionIDs,
	})
	if err != nil {
		return fmt.Errorf("mark uploads abandoned: %w", err)
	}
	storageKeys, err := qtx.DeleteUploadingSecrets(ctx, validTexts(publicIDs))
	if err != nil {
		return fmt.Errorf("delete abandoned uploads' secrets: %w", err)
	}
	if err := qtx.DoomObjects(ctx, validTexts(storageKeys)); err != nil {
		return fmt.Errorf("doom abandoned uploads' objects: %w", err)
	}
	return nil
}

func uploadFromRow(row dbsqlc.GetUploadRow) *domain.Upload {
	return &domain.Upload{
		SessionID:       row.SessionID,
		PublicID:        row.PublicID.String,
		UploadTokenHash: row.UploadTokenHash,
		State:           domain.UploadState(row.State),
		ExpiresAt:       row.ExpiresAt.Time,
		FinishedAt:      pointerFromTimestamp(row.FinishedAt),
		StorageKey:      row.StorageKey.String,
		S3UploadID:      row.S3UploadID.String,
		BlobSize:        row.BlobSize.Int64,
		SecretExpiresAt: row.SecretExpiresAt.Time,
	}
}

func uploadPartsFromRows(rows []dbsqlc.UploadPart) []domain.UploadPart {
	parts := make([]domain.UploadPart, 0, len(rows))
	for _, row := range rows {
		parts = append(parts, *uploadPartFromRow(row))
	}
	return parts
}

func uploadPartFromRow(row dbsqlc.UploadPart) *domain.UploadPart {
	return &domain.UploadPart{
		SessionID:  row.SessionID,
		PartNumber: int(row.PartNumber),
		Offset:     row.PartOffset,
		Size:       row.PartSize,
		SHA256:     row.PartSha256,
		ETag:       row.Etag,
	}
}
