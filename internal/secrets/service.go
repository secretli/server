package secrets

import (
	"context"
	"fmt"
	"github.com/secretli/server/internal"
)

type Service struct {
	repository internal.SecretRepository
}

func NewService(repository internal.SecretRepository) *Service {
	return &Service{repository: repository}
}

func (s *Service) Store(ctx context.Context, secret internal.Secret) error {
	if err := s.repository.Store(ctx, secret); err != nil {
		return fmt.Errorf("store secret: %w", err)
	}
	return nil
}

func (s *Service) Retrieve(ctx context.Context, publicID string, retrievalToken string) (internal.Secret, error) {
	secret, err := s.repository.Get(ctx, publicID)
	if err != nil {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", err)
	}

	if secret.ExpiresAt.Before(internal.Clock.Now()) {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", internal.ErrInaccessibleSecret)
	}

	if secret.BurnAfterRead && secret.AlreadyRead {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", internal.ErrInaccessibleSecret)
	}

	if secret.RetrievalToken != retrievalToken {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", internal.ErrAuthorizationFailed)
	}

	if err = s.repository.MarkAsRead(ctx, publicID); err != nil {
		return internal.Secret{}, fmt.Errorf("retrieve secret: %w", err)
	}

	return secret, nil
}

func (s *Service) Delete(ctx context.Context, publicID string, retrievalToken string, deletionToken string) error {
	secret, err := s.repository.Get(ctx, publicID)
	if err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	if secret.RetrievalToken != retrievalToken {
		return fmt.Errorf("delete secret: %w: retrieval token mismatch", internal.ErrAuthorizationFailed)
	}
	if secret.DeletionToken != deletionToken {
		return fmt.Errorf("delete secret: %w: deletion token mismatch", internal.ErrAuthorizationFailed)
	}

	if err := s.repository.Delete(ctx, publicID); err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}
	return nil
}
