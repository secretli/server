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
	Nonce          string    `json:"nonce"`
	EncryptedData  string    `json:"encrypted_data"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type SecretRepository interface {
	Store(ctx context.Context, secret Secret) error
	Get(ctx context.Context, publicID string) (Secret, error)
}
