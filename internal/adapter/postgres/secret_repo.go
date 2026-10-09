package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/secretli/server/internal/adapter/postgres/dbsqlc"
	"github.com/secretli/server/internal/domain"
	tokencrypto "github.com/secretli/server/internal/platform/crypto"
)

// SecretRepo is the whole datastore: secrets, uploads, the objects they are
// written to, and transfers.
type SecretRepo struct {
	q    *dbsqlc.Queries
	pool *pgxpool.Pool
	// maxStoredBytes caps what all secrets together may take up in storage;
	// 0 means no cap.
	maxStoredBytes int64
}

// Option configures a SecretRepo.
type Option func(*SecretRepo)

// WithMaxStoredBytes caps what all secrets together may take up in storage:
// StartUpload refuses an upload that would go past it. 0 means no cap.
func WithMaxStoredBytes(n int64) Option {
	return func(r *SecretRepo) { r.maxStoredBytes = n }
}

func NewSecretRepo(pool *pgxpool.Pool, opts ...Option) *SecretRepo {
	r := &SecretRepo{q: dbsqlc.New(pool), pool: pool}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// MetricsStats returns the totals the metrics report.
func (r *SecretRepo) MetricsStats(ctx context.Context, now time.Time) (domain.MetricsStats, error) {
	row, err := r.q.MetricsStats(ctx, timestamptz(now))
	if err != nil {
		return domain.MetricsStats{}, fmt.Errorf("query metrics stats: %w", err)
	}
	return domain.MetricsStats{
		LiveOneTime:          row.LiveOneTime,
		LiveReusable:         row.LiveReusable,
		StoredBytes:          row.StoredBytes,
		OverdueSecrets:       row.OverdueSecrets,
		DoomedObjects:        row.DoomedObjects,
		RemovalFailedObjects: row.RemovalFailedObjects,
		StuckUploads:         row.StuckUploads,
		ReservedPublicIDs:    row.ReservedPublicIds,
	}, nil
}

func (r *SecretRepo) GetSecret(ctx context.Context, publicID string) (*domain.Secret, error) {
	row, err := r.q.GetSecret(ctx, publicID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query secret: %w", err)
	}
	return secretFromRow(row), nil
}

func (r *SecretRepo) StartRetrievalSession(ctx context.Context, publicID, blobTokenHash, deletionTokenHash, sessionTokenHash string, expiresAt, now time.Time) (*domain.Secret, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	row, err := qtx.GetReadableSecretForUpdate(ctx, dbsqlc.GetReadableSecretForUpdateParams{
		PublicID: publicID,
		NowAt:    timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query secret for retrieval session: %w", err)
	}
	secret := secretFromRow(row)

	if !tokencrypto.TokensEqual(blobTokenHash, secret.BlobTokenHash) {
		return nil, domain.ErrForbidden
	}
	// The owner opening their own reusable secret is not a recipient getting
	// it. A one-time secret closes whoever opens it.
	byOwner := deletionTokenHash != "" && tokencrypto.TokensEqual(deletionTokenHash, secret.DeletionTokenHash)

	switch {
	case secret.BurnAfterRead:
		// The answer still carries what the opener needs to read it.
		if err := qtx.CloseSecret(ctx, publicID); err != nil {
			return nil, fmt.Errorf("close opened one-time secret: %w", err)
		}
		secret.State = domain.SecretClosing
	case !byOwner && !secret.Opened:
		if err := qtx.MarkSecretOpened(ctx, publicID); err != nil {
			return nil, fmt.Errorf("mark secret opened: %w", err)
		}
		secret.Opened = true
	}

	if err := qtx.CreateRetrievalSession(ctx, dbsqlc.CreateRetrievalSessionParams{
		SessionTokenHash: sessionTokenHash,
		PublicID:         publicID,
		ExpiresAt:        timestamptz(expiresAt),
	}); err != nil {
		return nil, fmt.Errorf("insert retrieval session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit retrieval session: %w", err)
	}
	return secret, nil
}

func (r *SecretRepo) GetByRetrievalSession(ctx context.Context, publicID, sessionTokenHash string, now time.Time) (*domain.Secret, error) {
	row, err := r.q.GetDownloadableSecret(ctx, dbsqlc.GetDownloadableSecretParams{
		SessionTokenHash: sessionTokenHash,
		PublicID:         publicID,
		NowAt:            timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrForbidden
	}
	if err != nil {
		return nil, fmt.Errorf("query retrieval session: %w", err)
	}
	return secretFromRow(row), nil
}

func (r *SecretRepo) Delete(ctx context.Context, publicID string, now time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	qtx := r.q.WithTx(tx)

	row, err := qtx.GetReadableSecretForUpdate(ctx, dbsqlc.GetReadableSecretForUpdateParams{
		PublicID: publicID,
		NowAt:    timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("query secret for delete: %w", err)
	}
	// The cleanup removes the object from storage within a cycle; from now on
	// nothing reads it. The row goes, its retrieval sessions with it, and
	// nothing about the secret is kept.
	if _, err := deleteSecrets(ctx, qtx, []string{publicID}, []string{row.StorageKey}); err != nil {
		return fmt.Errorf("deleted secret: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete secret: %w", err)
	}
	return nil
}

func secretFromRow(row dbsqlc.Secret) *domain.Secret {
	return &domain.Secret{
		PublicID:          row.PublicID,
		State:             domain.SecretState(row.State),
		StorageKey:        row.StorageKey,
		MetadataTokenHash: row.MetadataTokenHash.String,
		BlobTokenHash:     row.BlobTokenHash.String,
		DeletionTokenHash: row.DeletionTokenHash.String,
		EncryptedMeta:     row.EncryptedMeta.String,
		BlobSize:          row.BlobSize,
		BurnAfterRead:     row.BurnAfterRead,
		ExpiresAt:         row.ExpiresAt.Time,
		CreatedAt:         pointerFromTimestamp(row.CreatedAt),
		Opened:            row.Opened,
	}
}

// validTexts returns the values that are set, skipping NULLs.
func validTexts(values []pgtype.Text) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v.Valid {
			out = append(out, v.String)
		}
	}
	return out
}

func pointerFromTimestamp(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	return &t.Time
}

func timestamptz(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func text(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

func interval(d time.Duration) pgtype.Interval {
	return pgtype.Interval{Microseconds: d.Microseconds(), Valid: true}
}

// durationFromInterval reads an interval as a duration, a day as 24 hours.
// The server writes intervals in microseconds only; one Postgres computed
// may carry days, and none carries months. NULL is 0.
func durationFromInterval(iv pgtype.Interval) time.Duration {
	if !iv.Valid {
		return 0
	}
	return time.Duration(iv.Microseconds)*time.Microsecond + time.Duration(iv.Days)*24*time.Hour
}

func isDuplicateKeyError(err error) bool {
	if err, ok := errors.AsType[*pgconn.PgError](err); ok {
		return err.Code == "23505"
	}
	return false
}
