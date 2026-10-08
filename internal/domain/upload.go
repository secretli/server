package domain

import "time"

// UploadState is where an upload session is.
type UploadState string

const (
	UploadUploading UploadState = "uploading"
	UploadCompleted UploadState = "completed"
	UploadAbandoned UploadState = "abandoned"
)

// UploadStatePending is how the API names an upload under way.
const UploadStatePending = "pending"

// Upload is an upload session: the multipart upload that creates a secret.
// A finished session stays for a while, so a repeated complete or abort gets
// the same answer.
type Upload struct {
	SessionID string
	// PublicID is the secret the upload creates; empty once it was abandoned.
	PublicID        string
	UploadTokenHash string
	State           UploadState
	ExpiresAt       time.Time
	FinishedAt      *time.Time

	// Of the secret and its object, while the secret has them.
	StorageKey      string
	S3UploadID      string
	BlobSize        int64
	SecretExpiresAt time.Time
}

type UploadPart struct {
	SessionID  string
	PartNumber int
	Offset     int64
	Size       int64
	SHA256     string
	ETag       string
	CreatedAt  time.Time
}
