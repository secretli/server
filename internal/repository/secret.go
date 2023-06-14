package repository

import (
	"context"
	"github.com/secretli/server/ent"
	"github.com/secretli/server/ent/secret"
	"github.com/secretli/server/internal"
	"time"
)

type DBSecretRepository struct {
	client *ent.Client
}

func NewDBSecretRepository(client *ent.Client) *DBSecretRepository {
	return &DBSecretRepository{client: client}
}

func (r *DBSecretRepository) Store(ctx context.Context, secret internal.Secret) error {
	return r.client.Secret.
		Create().
		SetPublicID(secret.PublicID).
		SetRetrievalToken(secret.RetrievalToken).
		SetDeletionToken(secret.DeletionToken).
		SetNonce(secret.Nonce).
		SetEncryptedData(secret.EncryptedData).
		SetExpiresAt(secret.ExpiresAt).
		SetBurnAfterRead(secret.BurnAfterRead).
		SetAlreadyRead(secret.AlreadyRead).
		Exec(ctx)
}

func (r *DBSecretRepository) Get(ctx context.Context, publicID string) (internal.Secret, error) {
	result, err := r.client.Secret.
		Query().
		Where(secret.PublicID(publicID)).
		Only(ctx)

	if ent.IsNotFound(err) {
		err = internal.ErrUnknownSecret
	}
	if err != nil {
		return internal.Secret{}, err
	}

	return internal.Secret{
		PublicID:       result.PublicID,
		RetrievalToken: result.RetrievalToken,
		DeletionToken:  result.DeletionToken,
		Nonce:          result.Nonce,
		EncryptedData:  result.EncryptedData,
		ExpiresAt:      result.ExpiresAt,
		BurnAfterRead:  result.BurnAfterRead,
		AlreadyRead:    result.AlreadyRead,
	}, nil
}

func (r *DBSecretRepository) MarkAsRead(ctx context.Context, publicID string) error {
	return r.client.Secret.
		Update().
		Where(secret.PublicID(publicID), secret.AlreadyRead(false)).
		Exec(ctx)
}

func (r *DBSecretRepository) Delete(ctx context.Context, publicID string) error {
	_, err := r.client.Secret.
		Delete().
		Where(secret.PublicID(publicID)).
		Exec(ctx)

	return err
}

func (r *DBSecretRepository) Cleanup(ctx context.Context, now time.Time) error {
	filter := secret.Or(
		secret.ExpiresAtLT(now),
		secret.And(
			secret.AlreadyRead(true),
			secret.BurnAfterRead(true),
		),
	)

	_, err := r.client.Secret.
		Delete().
		Where(filter).
		Exec(ctx)

	return err
}
