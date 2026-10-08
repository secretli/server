package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"

	"github.com/secretli/server/internal/adapter/metrics"
	"github.com/secretli/server/internal/domain"
	tokencrypto "github.com/secretli/server/internal/platform/crypto"
	apperrors "github.com/secretli/server/internal/platform/errors"
)

const (
	HeaderPartOffset = "X-Part-Offset"
	HeaderPartSize   = "X-Part-Size"
	HeaderPartSHA256 = "X-Part-SHA256"

	uploadSessionTTL        = 24 * time.Hour
	multipartUploadPartSize = 32 * 1024 * 1024
	maxMultipartUploadPart  = multipartUploadPartSize + 1024*1024
	s3MinimumPartSize       = 5 * 1024 * 1024
	maxMultipartPartNumber  = 10000
)

type UploadHandler struct {
	repo        domain.UploadRepo
	fileStore   domain.MultipartFileStore
	maxFileSize int64
	metrics     *metrics.SecretMetrics
	validate    *validator.Validate
}

type createUploadSessionRequest struct {
	PublicID      string `json:"public_id" validate:"required,public_id"`
	MetadataToken string `json:"metadata_token" validate:"required,secret_token"`
	BlobToken     string `json:"blob_token" validate:"required,secret_token"`
	DeletionToken string `json:"deletion_token" validate:"required,secret_token"`
	EncryptedMeta string `json:"encrypted_meta" validate:"required,encrypted_meta"`
	Expiration    string `json:"expiration" validate:"required,expiration"`
	BurnAfterRead bool   `json:"burn_after_read"`
	BlobSize      int64  `json:"blob_size"`
}

func NewUploadHandler(repo domain.UploadRepo, fileStore domain.MultipartFileStore, maxFileSize int64, m *metrics.SecretMetrics) *UploadHandler {
	return &UploadHandler{
		repo:        repo,
		fileStore:   fileStore,
		maxFileSize: maxFileSize,
		metrics:     m,
		validate:    newValidator(),
	}
}

func (h *UploadHandler) CreateUploadSession(c echo.Context) error {
	var req createUploadSessionRequest
	if err := c.Bind(&req); err != nil {
		return apperrors.BadRequestError("invalid request body")
	}
	if details := h.validateRequest(&req); details != nil {
		return validationError(details)
	}
	if req.BlobSize <= 0 {
		return apperrors.BadRequestError("blob_size must be positive")
	}
	if req.BlobSize > h.maxFileSize {
		return apperrors.BadRequestError("file exceeds maximum size limit")
	}

	duration, err := parseExpiration(req.Expiration)
	if err != nil {
		return apperrors.BadRequestError(err.Error())
	}

	sessionID, err := newRetrievalSessionToken()
	if err != nil {
		return apperrors.InternalError("failed to create upload session", err)
	}
	uploadToken, err := newRetrievalSessionToken()
	if err != nil {
		return apperrors.InternalError("failed to create upload session", err)
	}

	ctx := c.Request().Context()
	now := time.Now()
	storageKey := domain.UploadStorageKey(sessionID)
	secret := &domain.Secret{
		PublicID:          req.PublicID,
		State:             domain.SecretUploading,
		StorageKey:        storageKey,
		MetadataTokenHash: tokencrypto.TokenHash(req.MetadataToken),
		BlobTokenHash:     tokencrypto.TokenHash(req.BlobToken),
		DeletionTokenHash: tokencrypto.TokenHash(req.DeletionToken),
		EncryptedMeta:     req.EncryptedMeta,
		BlobSize:          req.BlobSize,
		BurnAfterRead:     req.BurnAfterRead,
		ExpiresAt:         now.Add(duration),
	}
	upload := &domain.Upload{
		SessionID:       sessionID,
		PublicID:        req.PublicID,
		UploadTokenHash: tokencrypto.TokenHash(uploadToken),
		State:           domain.UploadUploading,
		ExpiresAt:       now.Add(uploadSessionTTL),
		StorageKey:      storageKey,
		BlobSize:        req.BlobSize,
		SecretExpiresAt: secret.ExpiresAt,
	}

	// The secret, the upload and its object are on file before anything
	// reaches storage: a taken public id is refused first, and nothing written
	// can be lost track of.
	if err := h.repo.StartUpload(ctx, secret, upload, now); err != nil {
		if errors.Is(err, domain.ErrDuplicate) {
			return apperrors.ConflictError("secret with this public_id already exists")
		}
		return apperrors.InternalError("failed to create upload session", err)
	}

	uploadID, err := h.fileStore.CreateMultipartUpload(ctx, storageKey)
	if err != nil {
		h.abandon(ctx, sessionID)
		return apperrors.InternalError("failed to create multipart upload", err)
	}
	if err := h.repo.RecordS3UploadID(ctx, storageKey, uploadID); err != nil {
		// The cleanup finds the multipart upload by its key.
		h.abandon(ctx, sessionID)
		return apperrors.InternalError("failed to create upload session", err)
	}
	upload.S3UploadID = uploadID

	return c.JSON(http.StatusCreated, uploadSessionResponse(upload, uploadToken))
}

func (h *UploadHandler) UploadPart(c echo.Context) error {
	upload, parts, _, err := h.authenticateUploadSession(c)
	if err != nil {
		return err
	}
	if err := validatePendingUpload(upload); err != nil {
		return err
	}

	partNumber, err := parsePartNumber(c.Param("partNumber"))
	if err != nil {
		return apperrors.BadRequestError(err.Error())
	}
	offset, err := parseInt64Header(c.Request(), HeaderPartOffset)
	if err != nil {
		return apperrors.BadRequestError(err.Error())
	}
	size, err := parseInt64Header(c.Request(), HeaderPartSize)
	if err != nil {
		return apperrors.BadRequestError(err.Error())
	}
	if size <= 0 || size > maxMultipartUploadPart || size > h.maxFileSize {
		return apperrors.BadRequestError("invalid " + HeaderPartSize + " header")
	}
	if err := validatePartPlacement(upload.BlobSize, partNumber, offset, size); err != nil {
		return apperrors.BadRequestError(err.Error())
	}
	if c.Request().ContentLength >= 0 && c.Request().ContentLength != size {
		return apperrors.BadRequestError("request body size does not match " + HeaderPartSize)
	}
	partSHA256 := c.Request().Header.Get(HeaderPartSHA256)
	if !isSHA256Hex(partSHA256) {
		return apperrors.BadRequestError("invalid " + HeaderPartSHA256 + " header")
	}

	for _, existing := range parts {
		if existing.PartNumber != partNumber {
			continue
		}
		if existing.Offset == offset && existing.Size == size && existing.SHA256 == partSHA256 {
			return c.JSON(http.StatusOK, uploadPartResponse(existing))
		}
		return apperrors.ConflictError("part already uploaded with different content")
	}

	partFile, cleanup, err := spoolValidatedPart(c, size, partSHA256)
	if err != nil {
		return err
	}
	defer cleanup()

	etag, err := h.fileStore.UploadPart(
		c.Request().Context(),
		upload.StorageKey,
		upload.S3UploadID,
		partNumber,
		partFile,
		size,
	)
	if err != nil {
		return apperrors.InternalError("failed to upload part to S3", err)
	}

	recorded, err := h.repo.RecordUploadPart(c.Request().Context(), &domain.UploadPart{
		SessionID:  upload.SessionID,
		PartNumber: partNumber,
		Offset:     offset,
		Size:       size,
		SHA256:     partSHA256,
		ETag:       etag,
	})
	if errors.Is(err, domain.ErrConflict) {
		return apperrors.ConflictError("part already uploaded with different content")
	}
	if err != nil {
		return apperrors.InternalError("failed to record uploaded part", err)
	}

	return c.JSON(http.StatusOK, uploadPartResponse(*recorded))
}

func (h *UploadHandler) CompleteUploadSession(c echo.Context) error {
	upload, _, _, err := h.authenticateUploadSession(c)
	if err != nil {
		return err
	}

	ctx := c.Request().Context()
	// stored records that storage assembled the object, so a later failure
	// leaves an object that no live secret references.
	stored := false
	completed, err := h.repo.CompleteUpload(ctx, upload.SessionID, time.Now(), func(locked *domain.Upload, parts []domain.UploadPart) error {
		if time.Now().After(locked.ExpiresAt) {
			return apperrors.ConflictError("upload session has expired")
		}
		completedParts, err := validateUploadParts(locked, parts)
		if err != nil {
			return apperrors.BadRequestError(err.Error())
		}
		if err := h.fileStore.CompleteMultipartUpload(ctx, locked.StorageKey, locked.S3UploadID, completedParts); err != nil {
			return err
		}
		stored = true
		return nil
	})
	if err != nil {
		return h.completeUploadFailed(ctx, upload, stored, err)
	}

	// A repeated complete finds the upload already completed and answers the
	// same way without creating anything.
	if stored {
		h.metrics.SecretsCreated.Inc()
	}
	// Only a repeat long after the secret expired finds it gone.
	if completed.SecretExpiresAt.IsZero() {
		return apperrors.ConflictError("upload session already completed")
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"expires_at": completed.SecretExpiresAt.UTC().Format(time.RFC3339),
	})
}

func (h *UploadHandler) completeUploadFailed(ctx context.Context, upload *domain.Upload, stored bool, err error) error {
	if stored {
		// Storage assembled the object, but the secret did not go live.
		h.abandon(ctx, upload.SessionID)
		return apperrors.InternalError("failed to create secret", err)
	}

	switch {
	case errors.Is(err, domain.ErrNotFound):
		return apperrors.NotFoundError("upload session not found")
	case errors.Is(err, domain.ErrConflict):
		return apperrors.ConflictError("upload session is not pending")
	case errors.Is(err, domain.ErrInvalidParts):
		// Recorded parts no longer match storage (for example a concurrent
		// re-upload of the same part number with different content). Forget
		// them so the client can upload the parts again.
		if clearErr := h.repo.ClearUploadParts(ctx, upload.SessionID); clearErr != nil {
			return apperrors.InternalError("failed to reset upload parts", clearErr)
		}
		return apperrors.ConflictError("uploaded parts were rejected by storage; upload the parts again")
	case errors.Is(err, domain.ErrUploadNotFound):
		h.abandon(ctx, upload.SessionID)
		return apperrors.ConflictError("upload session is no longer valid; start a new upload")
	}
	if appErr, ok := errors.AsType[*apperrors.Error](err); ok {
		return appErr
	}
	return apperrors.InternalError("failed to complete multipart upload", err)
}

// abandon ends an upload that can no longer become a secret. Its object is
// doomed with it, and the cleanup removes whatever storage holds under its
// key. If this fails too (the database is down, say), the upload's expiry
// does the same; if a concurrent request completed the upload meanwhile, the
// object belongs to that secret and stays.
func (h *UploadHandler) abandon(ctx context.Context, sessionID string) {
	if err := h.repo.AbortUpload(ctx, sessionID, time.Now()); err != nil && !errors.Is(err, domain.ErrConflict) {
		slog.ErrorContext(ctx, "failed to abandon upload", "error", err)
	}
}

func (h *UploadHandler) AbortUploadSession(c echo.Context) error {
	upload, _, _, err := h.authenticateUploadSession(c)
	if err != nil {
		return err
	}
	// The multipart upload and anything stored go with the object, which the
	// cleanup removes within a cycle.
	err = h.repo.AbortUpload(c.Request().Context(), upload.SessionID, time.Now())
	if errors.Is(err, domain.ErrConflict) {
		return apperrors.ConflictError("upload session already completed")
	}
	if errors.Is(err, domain.ErrNotFound) {
		return apperrors.NotFoundError("upload session not found")
	}
	if err != nil {
		return apperrors.InternalError("failed to abort upload session", err)
	}
	return c.NoContent(http.StatusNoContent)
}

func (h *UploadHandler) authenticateUploadSession(c echo.Context) (*domain.Upload, []domain.UploadPart, string, error) {
	sessionID := c.Param("sessionID")
	if sessionID == "" {
		return nil, nil, "", apperrors.BadRequestError("missing session_id")
	}
	if !domain.ValidToken(sessionID) {
		return nil, nil, "", apperrors.BadRequestError("malformed session_id")
	}

	uploadToken, err := bearerToken(c.Request().Header.Get("Authorization"))
	if err != nil {
		return nil, nil, "", apperrors.BadRequestError(err.Error())
	}
	if !domain.ValidToken(uploadToken) {
		return nil, nil, "", apperrors.BadRequestError("malformed Authorization header")
	}

	upload, parts, err := h.repo.GetUpload(c.Request().Context(), sessionID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, nil, "", apperrors.NotFoundError("upload session not found")
	}
	if err != nil {
		return nil, nil, "", apperrors.InternalError("failed to get upload session", err)
	}
	if !tokencrypto.TokensEqual(tokencrypto.TokenHash(uploadToken), upload.UploadTokenHash) {
		return nil, nil, "", apperrors.ForbiddenError("invalid upload token")
	}
	return upload, parts, uploadToken, nil
}

func (h *UploadHandler) validateRequest(v any) []string {
	err := h.validate.Struct(v)
	if err == nil {
		return nil
	}
	errs, ok := errors.AsType[validator.ValidationErrors](err)
	if !ok {
		return []string{"unknown validation error"}
	}
	details := make([]string, len(errs))
	for i, fe := range errs {
		details[i] = fieldErrorMessage(fe)
	}
	return details
}

func uploadSessionResponse(upload *domain.Upload, uploadToken string) map[string]any {
	return map[string]any{
		"session_id":        upload.SessionID,
		"public_id":         upload.PublicID,
		"part_size":         multipartUploadPartSize,
		"blob_size":         upload.BlobSize,
		"expires_at":        upload.SecretExpiresAt.UTC().Format(time.RFC3339),
		"upload_expires_at": upload.ExpiresAt.UTC().Format(time.RFC3339),
		"state":             domain.UploadStatePending,
		"upload_token":      uploadToken,
	}
}

func uploadPartResponse(part domain.UploadPart) map[string]any {
	return map[string]any{
		"part_number": part.PartNumber,
		"offset":      part.Offset,
		"size":        part.Size,
		"sha256":      part.SHA256,
		"etag":        part.ETag,
	}
}

func validatePendingUpload(upload *domain.Upload) error {
	// Without a recorded multipart upload the start failed half-way.
	if upload.State != domain.UploadUploading || upload.S3UploadID == "" {
		return apperrors.ConflictError("upload session is not pending")
	}
	if time.Now().After(upload.ExpiresAt) {
		return apperrors.ConflictError("upload session has expired")
	}
	return nil
}

func validateUploadParts(upload *domain.Upload, parts []domain.UploadPart) ([]domain.CompletedPart, error) {
	if len(parts) == 0 {
		return nil, errors.New("upload session has no parts")
	}
	sort.Slice(parts, func(i, j int) bool {
		return parts[i].PartNumber < parts[j].PartNumber
	})

	completed := make([]domain.CompletedPart, 0, len(parts))
	var expectedOffset int64
	for i, part := range parts {
		expectedPartNumber := i + 1
		if part.PartNumber != expectedPartNumber {
			return nil, fmt.Errorf("missing upload part %d", expectedPartNumber)
		}
		if part.Offset != expectedOffset {
			return nil, fmt.Errorf("upload part %d has invalid offset", part.PartNumber)
		}
		if i < len(parts)-1 && part.Size < s3MinimumPartSize {
			return nil, fmt.Errorf("upload part %d is below minimum size", part.PartNumber)
		}
		expectedOffset += part.Size
		if expectedOffset > upload.BlobSize {
			return nil, errors.New("uploaded parts exceed expected size")
		}
		completed = append(completed, domain.CompletedPart{
			PartNumber: part.PartNumber,
			ETag:       part.ETag,
		})
	}
	if expectedOffset != upload.BlobSize {
		return nil, errors.New("upload is missing parts")
	}
	return completed, nil
}

// validatePartPlacement rejects parts that cannot belong to a valid final
// layout of blobSize bytes. Without it a session declaring a tiny blob could
// push thousands of full-size parts into storage until the session expires.
func validatePartPlacement(blobSize int64, partNumber int, offset, size int64) error {
	maxParts := (blobSize + s3MinimumPartSize - 1) / s3MinimumPartSize
	if maxParts < 1 {
		maxParts = 1
	}
	if int64(partNumber) > maxParts {
		return errors.New("part number exceeds the number of parts for the declared blob size")
	}
	// Every part before this one is non-final and therefore at least the S3
	// minimum, so the offset has a hard lower bound.
	if offset < int64(partNumber-1)*s3MinimumPartSize {
		return errors.New("invalid " + HeaderPartOffset + " header")
	}
	if offset+size > blobSize {
		return errors.New("part exceeds the declared blob size")
	}
	if offset+size < blobSize && size < s3MinimumPartSize {
		return errors.New("non-final part is below the minimum part size")
	}
	return nil
}

func parsePartNumber(value string) (int, error) {
	partNumber, err := strconv.Atoi(value)
	if err != nil || partNumber <= 0 || partNumber > maxMultipartPartNumber {
		return 0, errors.New("invalid part number")
	}
	return partNumber, nil
}

func parseInt64Header(r *http.Request, header string) (int64, error) {
	value := r.Header.Get(header)
	if value == "" {
		return 0, errors.New("missing " + header + " header")
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return 0, errors.New("invalid " + header + " header")
	}
	return parsed, nil
}

func spoolValidatedPart(c echo.Context, expectedSize int64, expectedSHA256 string) (*os.File, func(), error) {
	partFile, err := os.CreateTemp("", "secretli-upload-part-*")
	if err != nil {
		return nil, nil, apperrors.InternalError("failed to create temporary upload part", err)
	}
	cleanup := func() {
		_ = partFile.Close()
		_ = os.Remove(partFile.Name())
	}

	body := http.MaxBytesReader(c.Response(), c.Request().Body, expectedSize+1)
	hasher := sha256.New()
	written, err := io.Copy(partFile, io.TeeReader(body, hasher))
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		cleanup()
		return nil, nil, apperrors.BadRequestError("part exceeds declared size")
	}
	if err != nil {
		cleanup()
		return nil, nil, apperrors.BadRequestError("failed to read part body")
	}
	if written > expectedSize {
		cleanup()
		return nil, nil, apperrors.BadRequestError("part exceeds declared size")
	}
	if written != expectedSize {
		cleanup()
		return nil, nil, apperrors.BadRequestError("request body size does not match " + HeaderPartSize)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != expectedSHA256 {
		cleanup()
		return nil, nil, apperrors.BadRequestError("part SHA-256 mismatch")
	}
	if _, err := partFile.Seek(0, io.SeekStart); err != nil {
		cleanup()
		return nil, nil, apperrors.InternalError("failed to prepare upload part", err)
	}
	return partFile, cleanup, nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if r >= '0' && r <= '9' {
			continue
		}
		if r >= 'a' && r <= 'f' {
			continue
		}
		return false
	}
	return true
}
