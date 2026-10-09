package domain

import "time"

// SecretState is where a secret is in its life.
type SecretState string

const (
	// SecretUploading: the upload is under way; nobody can read the secret yet.
	SecretUploading SecretState = "uploading"
	// SecretLive: the secret can be opened.
	SecretLive SecretState = "live"
	// SecretClosing: a one-time secret was opened. Nobody can open it again;
	// it keeps only its object, for the download that opened it, and goes
	// once that download has ended.
	SecretClosing SecretState = "closing"
)

// TimePrecision is how precisely the server keeps the times of secrets and
// uploads. To the microsecond, a secret's times would tell more than anybody
// needs, such as how long its upload took.
const TimePrecision = time.Minute

// KeptTime is t as the server keeps it: cut to the minute.
func KeptTime(t time.Time) time.Time {
	return t.Truncate(TimePrecision)
}

// SecretTimes returns when a secret whose upload completes at completedAt
// was created and when it expires. Its lifetime counts from the completed
// upload, and one more minute makes up for the cut, so a secret never lives
// shorter than chosen. Every secret of a lifetime keeps the same span between
// the two, so they tell nothing about its upload.
func SecretTimes(completedAt time.Time, lifetime time.Duration) (createdAt, expiresAt time.Time) {
	createdAt = KeptTime(completedAt)
	return createdAt, createdAt.Add(lifetime + TimePrecision)
}

// Secret is one secret, from the start of its upload until it is deleted or
// expires, or a one-time secret's last download ends. The server keeps
// ciphertext, token hashes, sizes and the expiry. Once a secret can no longer
// be opened, nothing tells that it ever existed.
type Secret struct {
	PublicID string
	State    SecretState
	// StorageKey is the secret's object; the secret goes when it is doomed.
	StorageKey string
	// The token hashes and the encrypted metadata are cleared when a
	// one-time secret closes.
	MetadataTokenHash string
	BlobTokenHash     string
	DeletionTokenHash string
	EncryptedMeta     string
	BlobSize          int64
	BurnAfterRead     bool
	// ExpiresAt is provisional while uploading; the completed upload sets it.
	ExpiresAt time.Time
	// CreatedAt is the minute the upload completed, set only while the secret
	// is live.
	CreatedAt *time.Time
	// Opened tells whether a recipient, not the owner, has opened a live
	// reusable secret. A one-time secret closes when it is opened instead.
	Opened bool
}

// Readable reports whether the secret can be read at now.
func (s *Secret) Readable(now time.Time) bool {
	return s.State == SecretLive && s.ExpiresAt.After(now)
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
