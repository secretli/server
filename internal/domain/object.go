package domain

import "time"

// ObjectState is how far an object got in storage.
type ObjectState string

const (
	// ObjectWriting: a multipart upload may be open under the key.
	ObjectWriting ObjectState = "writing"
	// ObjectStored: the upload is assembled into the object.
	ObjectStored ObjectState = "stored"
)

// Object is an object the server writes to storage, known from before the
// write until after the delete. Storage never holds one the database does
// not know about.
type Object struct {
	StorageKey string
	State      ObjectState
	// S3UploadID is the provider's multipart upload, once it is recorded.
	S3UploadID string
	CreatedAt  time.Time
	// DoomedAt is set once nothing may read the object any more.
	DoomedAt *time.Time
}
