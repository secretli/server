package secrets

import (
	"context"
	"fmt"
	"github.com/secretli/server/internal"
	"k8s.io/utils/clock"
	"time"
)

const (
	Day           = 24 * time.Hour
	MaxDataLength = 10000
)

type Service struct {
	clock      clock.Clock
	repository internal.SecretRepository
}

func NewService(clock clock.Clock, repository internal.SecretRepository) *Service {
	return &Service{clock: clock, repository: repository}
}

func (s *Service) Store(ctx context.Context, params internal.StoreSecretParameters) error {
	if len(params.EncryptedData) > MaxDataLength {
		return fmt.Errorf("store secret: %w", internal.ErrInvalidEncryptedData)
	}

	expiration, err := processExpirationDuration(params.Expiration)
	if err != nil {
		return fmt.Errorf("store secret: %w", err)
	}
	expiresAt := s.clock.Now().Add(expiration)

	secret := internal.Secret{
		PublicID:       params.PublicID,
		RetrievalToken: params.RetrievalToken,
		DeletionToken:  params.DeletionToken,
		Nonce:          params.Nonce,
		EncryptedData:  params.EncryptedData,
		ExpiresAt:      expiresAt,
		BurnAfterRead:  params.BurnAfterRead,
		AlreadyRead:    false,
	}

	if err := s.repository.Store(ctx, secret); err != nil {
		return fmt.Errorf("store secret: %w", err)
	}

	return nil
}

func (s *Service) Retrieve(ctx context.Context, params internal.RetrieveSecretParameters) (internal.Secret, error) {
	secret, err := s.repository.Get(ctx, params.SecretID)
	if err != nil {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", err)
	}

	if secret.ExpiresAt.Before(time.Now()) {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", internal.ErrInaccessibleSecret)
	}

	if secret.BurnAfterRead && secret.AlreadyRead {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", internal.ErrInaccessibleSecret)
	}

	if secret.RetrievalToken != params.RetrievalToken {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", internal.ErrAuthorizationFailed)
	}

	if err = s.repository.MarkAsRead(ctx, params.SecretID); err != nil {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", err)
	}

	return secret, nil
}

func (s *Service) Delete(ctx context.Context, params internal.DeleteSecretParameters) error {
	secret, err := s.repository.Get(ctx, params.SecretID)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	if secret.RetrievalToken != params.RetrievalToken {
		return fmt.Errorf("delete secret: %w: retrieval token mismatch", internal.ErrAuthorizationFailed)
	}
	if secret.DeletionToken != params.DeletionToken {
		return fmt.Errorf("delete secret: %w: deletion token mismatch", internal.ErrAuthorizationFailed)
	}

	if err := s.repository.Delete(ctx, params.SecretID); err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}

func processExpirationDuration(expiration string) (time.Duration, error) {
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
		return 0, internal.ErrInvalidExpiration
	}

	return duration, nil
}
