package internal

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnknownSecret        = errors.New("unknown secret")
	ErrInaccessibleSecret   = errors.New("inaccessible secret")
	ErrInvalidExpiration    = errors.New("invalid expiration")
	ErrInvalidEncryptedData = errors.New("invalid encrypted data")
	ErrAuthorizationFailed  = errors.New("authorization failed")
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

type StoreSecretParameters struct {
	PublicID       string `json:"public_id"`
	RetrievalToken string `json:"retrieval_token"`
	DeletionToken  string `json:"deletion_token"`
	Nonce          string `json:"nonce"`
	EncryptedData  string `json:"encrypted_data"`
	Expiration     string `json:"expiration"`
	BurnAfterRead  bool   `json:"burn_after_read"`
}

type RetrieveSecretParameters struct {
	SecretID       string
	RetrievalToken string
}

type DeleteSecretParameters struct {
	SecretID       string
	RetrievalToken string
	DeletionToken  string
}

type SecretService interface {
	Store(ctx context.Context, params StoreSecretParameters) error
	Retrieve(ctx context.Context, params RetrieveSecretParameters) (Secret, error)
	Delete(ctx context.Context, params DeleteSecretParameters) error
}
