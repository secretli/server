package repository

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/repository/database"
)

type DBSecretRepository struct {
	queries *database.Queries
}

func NewDBSecretRepository(pool *pgxpool.Pool) *DBSecretRepository {
	return &DBSecretRepository{queries: database.New(pool)}
}

func (r *DBSecretRepository) Store(ctx context.Context, secret internal.Secret) error {
	return r.queries.StoreSecret(ctx, database.StoreSecretParams{
		PublicID:       secret.PublicID,
		RetrievalToken: secret.RetrievalToken,
		Nonce:          secret.Nonce,
		EncryptedData:  secret.EncryptedData,
		ExpiresAt:      secret.ExpiresAt,
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
	}, nil
}
