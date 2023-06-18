package internal

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestNewSecret(t *testing.T) {
	t.Run("works", func(t *testing.T) {
		secret, err := NewSecret(SecretSpecification{
			PublicID:       "public_id",
			RetrievalToken: "retrieval_token",
			DeletionToken:  "deletion_token",
			Nonce:          "nonce",
			EncryptedData:  "some-encrypted-data",
			Expiration:     "5m",
			BurnAfterRead:  false,
		})
		assert.NoError(t, err)
		assert.EqualValues(t, "public_id", secret.PublicID)
		assert.EqualValues(t, false, secret.AlreadyRead)
	})

	t.Run("check valid expiration set", func(t *testing.T) {
		validExpirations := []string{"5m", "10m", "15m", "1h", "4h", "12h", "1d", "3d", "7d"}
		specification := SecretSpecification{
			PublicID:       "public_id",
			RetrievalToken: "retrieval_token",
			DeletionToken:  "deletion_token",
			Nonce:          "nonce",
			EncryptedData:  "some-encrypted-data",
		}

		for _, expiration := range validExpirations {
			specification.Expiration = expiration
			_, err := NewSecret(specification)
			assert.NoError(t, err)
		}
	})

	t.Run("check required fields", func(t *testing.T) {
		_, err := NewSecret(SecretSpecification{
			PublicID:       "public_id",
			RetrievalToken: "retrieval_token",
			DeletionToken:  "",
			Nonce:          "nonce",
			EncryptedData:  "some-encrypted-data",
			Expiration:     "5m",
			BurnAfterRead:  false,
		})
		assert.Error(t, err)
	})

	t.Run("error if data is too short", func(t *testing.T) {
		_, err := NewSecret(SecretSpecification{
			PublicID:       "public_id",
			RetrievalToken: "retrieval_token",
			DeletionToken:  "deletion_token",
			Nonce:          "nonce",
			EncryptedData:  "",
			Expiration:     "5m",
			BurnAfterRead:  false,
		})
		assert.ErrorIs(t, err, ErrInvalidEncryptedData)
	})

	t.Run("error if data is too long", func(t *testing.T) {
		data := strings.Repeat("x", MaxDataLength+1)
		_, err := NewSecret(SecretSpecification{
			PublicID:       "public_id",
			RetrievalToken: "retrieval_token",
			DeletionToken:  "deletion_token",
			Nonce:          "nonce",
			EncryptedData:  data,
			Expiration:     "5m",
			BurnAfterRead:  false,
		})
		assert.ErrorIs(t, err, ErrInvalidEncryptedData)
	})

	t.Run("error if invalid expiration", func(t *testing.T) {
		_, err := NewSecret(SecretSpecification{
			PublicID:       "public_id",
			RetrievalToken: "retrieval_token",
			DeletionToken:  "deletion_token",
			Nonce:          "nonce",
			EncryptedData:  "some-encrypted-data",
			Expiration:     "7m",
			BurnAfterRead:  false,
		})
		assert.ErrorIs(t, err, ErrInvalidExpiration)
	})
}
