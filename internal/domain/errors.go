package domain

import "errors"

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("duplicate")
	ErrForbidden = errors.New("forbidden")
	ErrConflict  = errors.New("conflict")
	// ErrStorageFull means a new upload would take storage past its cap.
	ErrStorageFull = errors.New("storage full")

	// ErrInvalidParts is returned by a MultipartFileStore when the storage
	// backend rejects the recorded parts on completion (stale ETag, wrong
	// order, undersized part). The parts must be uploaded again.
	ErrInvalidParts = errors.New("invalid multipart parts")
	// ErrUploadNotFound is returned by a MultipartFileStore when the backend
	// no longer knows the multipart upload (already completed or aborted).
	ErrUploadNotFound = errors.New("multipart upload not found")
	// ErrStorageUnavailable is returned by a FileStore when storage could not
	// be reached or answered with a server error or throttling: the same call
	// is worth repeating later.
	ErrStorageUnavailable = errors.New("storage unavailable")
)

// MaxWrongBlobTokens is how many wrong blob tokens a secret takes: at the
// last one it is deleted, so that a password can't be guessed at for the
// secret's whole lifetime. A wrong blob token is a wrong password as a
// rule, otherwise a damaged link.
const MaxWrongBlobTokens = 10

// WrongBlobTokenError is a wrong blob token. It is ErrForbidden, and says
// how many more the secret takes; 0 when this one deleted it.
type WrongBlobTokenError struct {
	AttemptsLeft int
}

func (e *WrongBlobTokenError) Error() string { return "wrong blob token" }

func (e *WrongBlobTokenError) Is(target error) bool { return target == ErrForbidden }
