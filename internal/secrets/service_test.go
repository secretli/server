package secrets

import (
	"context"
	"errors"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"
)

func TestService_Store(t *testing.T) {
	ctx := context.Background()

	t.Run("works", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		repo.On("Store", mock.Anything, mock.Anything).Return(nil)

		err := sut.Store(ctx, internal.Secret{})
		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		expectedError := errors.New("some error")

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		repo.On("Store", mock.Anything, mock.Anything).Return(expectedError)

		err := sut.Store(ctx, internal.Secret{})
		assert.ErrorIs(t, err, expectedError)
	})
}

func TestService_Retrieve(t *testing.T) {
	ctx := context.Background()

	t.Run("works", func(t *testing.T) {
		clock := mocks.NewClock(t)
		internal.Clock = clock

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			AlreadyRead:    false,
		}

		repo.
			On("Get", mock.Anything, secret.PublicID).Return(secret, nil).
			On("MarkAsRead", mock.Anything, secret.PublicID).Return(nil)

		clock.On("Now").Return(time.Time{})

		result, err := sut.Retrieve(ctx, secret.PublicID, secret.RetrievalToken)
		assert.NoError(t, err)
		assert.EqualValues(t, secret.PublicID, result.PublicID)
	})

	t.Run("fails if get fails", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		expectedError := errors.New("some error")
		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			AlreadyRead:    false,
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(internal.Secret{}, expectedError)

		_, err := sut.Retrieve(ctx, secret.PublicID, secret.RetrievalToken)
		assert.ErrorIs(t, err, expectedError)
	})

	t.Run("fails if mark as read fails", func(t *testing.T) {
		clock := mocks.NewClock(t)
		internal.Clock = clock

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		expectedError := errors.New("some error")
		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			AlreadyRead:    false,
		}

		repo.
			On("Get", mock.Anything, secret.PublicID).Return(secret, nil).
			On("MarkAsRead", mock.Anything, secret.PublicID).Return(expectedError)

		clock.On("Now").Return(time.Time{})

		_, err := sut.Retrieve(ctx, secret.PublicID, secret.RetrievalToken)
		assert.ErrorIs(t, err, expectedError)
	})

	t.Run("only allow reading if not expired", func(t *testing.T) {
		clock := mocks.NewClock(t)
		internal.Clock = clock

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		now := time.Now()
		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			ExpiresAt:      now.Add(-5 * time.Hour),
			AlreadyRead:    false,
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(secret, nil)
		clock.On("Now").Return(now)

		_, err := sut.Retrieve(ctx, secret.PublicID, secret.RetrievalToken)
		assert.ErrorIs(t, err, internal.ErrInaccessibleSecret)
	})

	t.Run("can read unread burn-after-read secret", func(t *testing.T) {
		clock := mocks.NewClock(t)
		internal.Clock = clock

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			AlreadyRead:    false,
			BurnAfterRead:  true,
		}

		repo.
			On("Get", mock.Anything, secret.PublicID).Return(secret, nil).
			On("MarkAsRead", mock.Anything, secret.PublicID).Return(nil)

		clock.On("Now").Return(time.Time{})

		result, err := sut.Retrieve(ctx, secret.PublicID, secret.RetrievalToken)
		assert.NoError(t, err)
		assert.EqualValues(t, secret.PublicID, result.PublicID)
	})

	t.Run("cannot read an already read burn-after-read secret", func(t *testing.T) {
		clock := mocks.NewClock(t)
		internal.Clock = clock

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			AlreadyRead:    true,
			BurnAfterRead:  true,
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(secret, nil)
		clock.On("Now").Return(time.Time{})

		_, err := sut.Retrieve(ctx, secret.PublicID, secret.RetrievalToken)
		assert.ErrorIs(t, err, internal.ErrInaccessibleSecret)
	})

	t.Run("access denies if retrieval token does not match", func(t *testing.T) {
		clock := mocks.NewClock(t)
		internal.Clock = clock

		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(secret, nil)
		clock.On("Now").Return(time.Time{})

		_, err := sut.Retrieve(ctx, secret.PublicID, "wrong-retrieval-token")
		assert.ErrorIs(t, err, internal.ErrAuthorizationFailed)
	})
}

func TestService_Delete(t *testing.T) {
	ctx := context.Background()

	t.Run("works", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			DeletionToken:  "test-deletion-token",
		}

		repo.
			On("Get", mock.Anything, secret.PublicID).Return(secret, nil).
			On("Delete", mock.Anything, secret.PublicID).Return(nil)

		err := sut.Delete(ctx, secret.PublicID, secret.RetrievalToken, secret.DeletionToken)
		assert.NoError(t, err)
	})

	t.Run("fails if getting from underlying repo fails", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		expectedError := errors.New("some error")
		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			DeletionToken:  "test-deletion-token",
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(internal.Secret{}, expectedError)

		err := sut.Delete(ctx, secret.PublicID, secret.RetrievalToken, secret.DeletionToken)
		assert.ErrorIs(t, err, expectedError)
	})

	t.Run("fails if deletion from underlying repo fails", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		expectedError := errors.New("some error")
		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			DeletionToken:  "test-deletion-token",
		}

		repo.
			On("Get", mock.Anything, secret.PublicID).Return(secret, nil).
			On("Delete", mock.Anything, secret.PublicID).Return(expectedError)

		err := sut.Delete(ctx, secret.PublicID, secret.RetrievalToken, secret.DeletionToken)
		assert.ErrorIs(t, err, expectedError)
	})

	t.Run("retrieval token has to match", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(secret, nil)

		err := sut.Delete(ctx, secret.PublicID, "wrong-retrieval-token", secret.DeletionToken)
		assert.ErrorIs(t, err, internal.ErrAuthorizationFailed)
	})

	t.Run("deletion token has to match", func(t *testing.T) {
		repo := mocks.NewSecretRepository(t)
		sut := NewService(repo)

		secret := internal.Secret{
			PublicID:       "test-public-id",
			RetrievalToken: "test-retrieval-token",
			DeletionToken:  "test-deletion-token",
		}

		repo.On("Get", mock.Anything, secret.PublicID).Return(secret, nil)

		err := sut.Delete(ctx, secret.PublicID, secret.RetrievalToken, "wrong-deletion-token")
		assert.ErrorIs(t, err, internal.ErrAuthorizationFailed)
	})
}
