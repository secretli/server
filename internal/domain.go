package internal

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnknownSecret = errors.New("unknown secret")
)

type Secret struct {
	PublicID       string    `json:"public_id"`
	RetrievalToken string    `json:"retrieval_token"`
	DeletionToken  string    `json:"deletion_token"`
	Nonce          string    `json:"nonce"`
	EncryptedData  string    `json:"encrypted_data"`
	ExpiresAt      time.Time `json:"expires_at"`
	BurnAfterRead  bool      `json:"burn_after_read"`
	AlreadyRead    bool      `json:"already_read"`
}

type SecretRepository interface {
	Store(ctx context.Context, secret Secret) error
	Get(ctx context.Context, publicID string) (Secret, error)
	MarkAsRead(ctx context.Context, publicID string) error
	Delete(ctx context.Context, publicID string) error
}
