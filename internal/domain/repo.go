package domain

import (
	"context"
	"time"
)

// CleanupBatch is the outcome of one cleanup batch.
type CleanupBatch struct {
	// Found is how many rows were due, at most the batch limit.
	Found int
	// Removed is how many of them were cleaned up. The rest failed their
	// storage callback and are left for a later cycle.
	Removed int
}

// MetricsStats are totals for the metrics, as things stand when they are
// read: no secret is told apart and no time is kept.
type MetricsStats struct {
	// Secrets that can be opened now, one-time and reusable.
	LiveOneTime  int64
	LiveReusable int64
	// What the secrets holding an object take up in storage.
	StoredBytes int64
	// Secrets past their expiry that the cleanup has not forgotten yet.
	OverdueSecrets int64
	// Objects waiting for the cleanup to delete them from storage, and those
	// of them storage has refused to delete before.
	DoomedObjects        int64
	RemovalFailedObjects int64
	// Uploads still under way past their own expiry.
	StuckUploads int64
	// Public ids kept reserved for secrets that are gone.
	ReservedPublicIDs int64
}

type SecretRepo interface {
	// GetSecret returns the secret filed under publicID in whatever state, or
	// ErrNotFound.
	GetSecret(ctx context.Context, publicID string) (*Secret, error)
	// StartRetrievalSession checks the blob token of a readable secret and
	// opens a session to read its object. Opening a one-time secret closes
	// it; a recipient opening a reusable one marks it opened. deletionTokenHash,
	// when the caller has one, marks the owner, whose opening of a reusable
	// secret does not count. It returns ErrNotFound unless the secret is
	// readable and ErrForbidden for a wrong blob token.
	StartRetrievalSession(ctx context.Context, publicID, blobTokenHash, deletionTokenHash, sessionTokenHash string, expiresAt, now time.Time) (*Secret, error)
	// GetByRetrievalSession returns the secret a valid session may still
	// download, live or closing, or ErrForbidden.
	GetByRetrievalSession(ctx context.Context, publicID, sessionTokenHash string, now time.Time) (*Secret, error)
	// Delete deletes a readable secret and dooms its object, in one
	// transaction; nothing about the secret is kept. It returns ErrNotFound
	// if the secret is not readable (any more).
	Delete(ctx context.Context, publicID string, now time.Time) error
}

type UploadRepo interface {
	// StartUpload files the secret as uploading, the upload that creates it
	// and the object it is written to, in one transaction, before anything
	// reaches storage. It returns ErrDuplicate if the public id is taken: by a
	// secret in any state, or, until its expiry, by one that was opened or
	// deleted. It returns ErrStorageFull if storage is
	// capped and the secret would take it past the cap. When the upload
	// started is not kept.
	StartUpload(ctx context.Context, secret *Secret, upload *Upload) error
	// RecordS3UploadID notes the provider's multipart upload for an object
	// that is being written.
	RecordS3UploadID(ctx context.Context, storageKey, s3UploadID string) error
	GetUpload(ctx context.Context, sessionID string) (*Upload, []UploadPart, error)
	RecordUploadPart(ctx context.Context, part *UploadPart) (*UploadPart, error)
	// ClearUploadParts forgets every recorded part of an upload so the client
	// can upload them again after the backend rejected them.
	ClearUploadParts(ctx context.Context, sessionID string) error
	// CompleteUpload makes the upload's secret live while holding the
	// upload's row lock, so concurrent completes are serialized. finalize runs
	// under the lock with the recorded parts and must assemble the object;
	// its error is returned unchanged. Only if it succeeds does the secret go
	// live, in one transaction.
	//
	// A completed upload is returned without calling finalize, which makes a
	// repeated complete idempotent. An abandoned one yields ErrConflict.
	CompleteUpload(ctx context.Context, sessionID string, now time.Time, finalize func(upload *Upload, parts []UploadPart) error) (*Upload, error)
	// AbortUpload abandons an upload under way: its secret's row goes, which
	// frees the public id, and its object is doomed, in one transaction.
	// Aborting an abandoned upload succeeds again; a completed one yields
	// ErrConflict.
	AbortUpload(ctx context.Context, sessionID string, now time.Time) error
}

type TransferRepo interface {
	// CreateTransfer stores an open transfer, with the sender's offer, under
	// the smallest free nameplate up to maxNameplate, first closing transfers
	// that ran out. It returns ErrConflict when no nameplate is free and
	// ErrDuplicate when the transfer id is taken.
	CreateTransfer(ctx context.Context, t *Transfer, maxNameplate int, now time.Time) error
	// ClaimTransfer hands the active, unclaimed transfer under nameplate to a
	// receiver. It returns ErrConflict if that transfer was already claimed
	// and ErrNotFound if there is none.
	ClaimTransfer(ctx context.Context, nameplate int, receiverTokenHash string, now time.Time) (*Transfer, error)
	GetTransfer(ctx context.Context, transferID string) (*Transfer, error)
	// AnswerTransfer stores the receiver's answer if the transfer is active,
	// claimed and not answered yet, and reports whether it did.
	AnswerTransfer(ctx context.Context, transferID string, share, confirmation []byte, now time.Time) (bool, error)
	// DeliverTransfer stores the sealed link and closes the transfer as done
	// if it is active and answered, and reports whether it did.
	DeliverTransfer(ctx context.Context, transferID string, delivery []byte, now time.Time) (bool, error)
	// CloseTransfer ends an active transfer. It returns ErrNotFound if the
	// transfer does not exist or already ended.
	CloseTransfer(ctx context.Context, transferID, reason string, now time.Time) error
}

// Repo is the datastore the HTTP server uses, as wired at start-up.
// Consumers take the narrower interface they actually need.
type Repo interface {
	SecretRepo
	UploadRepo
	TransferRepo
}
