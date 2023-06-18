package internal

import (
	"context"
	"errors"
	"k8s.io/utils/clock"
	"time"
)

const (
	Day           = 24 * time.Hour
	MaxDataLength = 10000
)

var (
	Clock clock.Clock = clock.RealClock{}

	ErrUnknownSecret        = errors.New("unknown secret")
	ErrInaccessibleSecret   = errors.New("inaccessible secret")
	ErrInvalidJSON          = errors.New("invalid json")
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

type SecretSpecification struct {
	PublicID       string
	RetrievalToken string
	DeletionToken  string
	Nonce          string
	EncryptedData  string
	Expiration     string
	BurnAfterRead  bool
}

func NewSecret(spec SecretSpecification) (Secret, error) {
	if spec.PublicID == "" || spec.RetrievalToken == "" || spec.DeletionToken == "" || spec.Nonce == "" {
		// TODO: better error!
		return Secret{}, errors.New("invalid secret specification")
	}

	if !(1 <= len(spec.EncryptedData) && len(spec.EncryptedData) <= MaxDataLength) {
		return Secret{}, ErrInvalidEncryptedData
	}

	ed, err := validateExpiration(spec.Expiration)
	if err != nil {
		return Secret{}, err
	}
	expiresAt := Clock.Now().Add(ed)

	secret := Secret{
		PublicID:       spec.PublicID,
		RetrievalToken: spec.RetrievalToken,
		DeletionToken:  spec.DeletionToken,
		Nonce:          spec.Nonce,
		EncryptedData:  spec.EncryptedData,
		ExpiresAt:      expiresAt,
		BurnAfterRead:  spec.BurnAfterRead,
		AlreadyRead:    false,
	}

	return secret, nil
}

//go:generate mockery --name SecretRepository
type SecretRepository interface {
	Store(ctx context.Context, secret Secret) error
	Get(ctx context.Context, publicID string) (Secret, error)
	MarkAsRead(ctx context.Context, publicID string) error
	Delete(ctx context.Context, publicID string) error
}

//go:generate mockery --name SecretService
type SecretService interface {
	Store(ctx context.Context, secret Secret) error
	Retrieve(ctx context.Context, publicID string, token string) (Secret, error)
	Delete(ctx context.Context, publicID string, retrievalToken string, deletionToken string) error
}

func validateExpiration(expiration string) (time.Duration, error) {
	var duration time.Duration

	switch expiration {
	case "5m":
		duration = 5 * time.Minute
	case "10m":
		duration = 10 * time.Minute
	case "15m":
		duration = 15 * time.Minute
	case "1h":
		duration = 1 * time.Hour
	case "4h":
		duration = 4 * time.Hour
	case "12h":
		duration = 12 * time.Hour
	case "1d":
		duration = 1 * Day
	case "3d":
		duration = 3 * Day
	case "7d":
		duration = 7 * Day
	default:
		return 0, ErrInvalidExpiration
	}

	return duration, nil
}
