package repository

import (
	"context"
	"database/sql"
	"errors"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/repository/database"
)

type DBSecretRepository struct {
	pool    *pgxpool.Pool
	queries *database.Queries
}

func NewDBSecretRepository(pool *pgxpool.Pool) *DBSecretRepository {
	return &DBSecretRepository{
		pool:    pool,
		queries: database.New(pool),
	}
}

func (r *DBSecretRepository) Store(ctx context.Context, secret internal.Secret) error {
	return r.queries.StoreSecret(ctx, database.StoreSecretParams{
		PublicID:       secret.PublicID,
		RetrievalToken: secret.RetrievalToken,
		Nonce:          secret.Nonce,
		EncryptedData:  secret.EncryptedData,
		ExpiresAt:      secret.ExpiresAt,
		BurnAfterRead:  secret.BurnAfterRead,
		AlreadyRead:    secret.AlreadyRead,
		DeletionToken:  sql.NullString{String: secret.DeletionToken, Valid: true},
	})
}

func (r *DBSecretRepository) Get(ctx context.Context, publicID string) (internal.Secret, error) {
	dto, err := r.queries.GetSecret(ctx, publicID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = internal.ErrUnknownSecret
		}
		return internal.Secret{}, err
	}

	return internal.Secret{
		PublicID:       dto.PublicID,
		RetrievalToken: dto.RetrievalToken,
		Nonce:          dto.Nonce,
		EncryptedData:  dto.EncryptedData,
		ExpiresAt:      dto.ExpiresAt,
		BurnAfterRead:  dto.BurnAfterRead,
		AlreadyRead:    dto.AlreadyRead,
		DeletionToken:  dto.DeletionToken.String,
	}, nil
}

func (r *DBSecretRepository) MarkAsRead(ctx context.Context, publicID string) error {
	return r.queries.MarkAsRead(ctx, publicID)
}

func (r *DBSecretRepository) Delete(ctx context.Context, publicID string) error {
	return r.queries.DeleteSecret(ctx, publicID)
}
