package domain

import "time"

// SecretState is where a secret is in its life.
type SecretState string

const (
	// SecretUploading: the upload is under way; nobody can read the secret yet.
	SecretUploading SecretState = "uploading"
	// SecretLive: the secret can be opened.
	SecretLive SecretState = "live"
	// SecretEnded: a one-time secret was opened, or the owner deleted the
	// secret. Until it expires, its row only tells which.
	SecretEnded SecretState = "ended"
)

// Outcome is how an ended secret ended. Expiry is not one: once a secret
// expires, nothing about it is kept.
type Outcome string

const (
	OutcomeOpened  Outcome = "opened"
	OutcomeDeleted Outcome = "deleted"
)

// Secret is one secret, from the start of its upload until its expiry. The
// server keeps ciphertext, token hashes, sizes and the expiry, and once the
// secret ends only how it ended, never when.
type Secret struct {
	PublicID string
	State    SecretState
	// StorageKey is the secret's object, empty once the object is doomed.
	StorageKey        string
	MetadataTokenHash string
	// The blob and deletion token hashes and the encrypted metadata are
	// cleared when the secret ends.
	BlobTokenHash     string
	DeletionTokenHash string
	EncryptedMeta     string
	BlobSize          int64
	BurnAfterRead     bool
	ExpiresAt         time.Time
	// CreatedAt is when the upload completed; nil while uploading.
	CreatedAt *time.Time
	// Opened tells whether someone other than the owner has opened a reusable
	// secret. A one-time secret ends when it is opened instead.
	Opened bool
	// Outcome is set once the secret has ended.
	Outcome Outcome
}

// Readable reports whether the secret can be read at now.
func (s *Secret) Readable(now time.Time) bool {
	return s.State == SecretLive && s.ExpiresAt.After(now)
}

// Ended reports whether the secret has ended and not expired yet, so a link
// to it can still be told how it ended.
func (s *Secret) Ended(now time.Time) bool {
	return s.State == SecretEnded && s.ExpiresAt.After(now)
}

type SecretMetadataResponse struct {
	EncryptedMeta string `json:"encrypted_meta"`
	BlobSize      int64  `json:"blob_size"`
	BurnAfterRead bool   `json:"burn_after_read"`
	ExpiresAt     string `json:"expires_at"`
	CreatedAt     string `json:"created_at"`
	// Opened tells whether someone other than the owner has opened it.
	Opened bool `json:"opened"`
}
