package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/secretli/server/internal/domain"
	tokencrypto "github.com/secretli/server/internal/platform/crypto"
)

// uploadMockRepo implements domain.UploadRepo the way the database does: an
// upload, its secret and its object are separate rows, and GetUpload joins
// them, so an abandoned upload no longer sees its secret or object.
type uploadMockRepo struct {
	// mu stands in for the upload's row lock: CompleteUpload holds it while
	// finalize runs.
	mu      sync.Mutex
	uploads map[string]*domain.Upload
	parts   map[string]map[int]domain.UploadPart
	secrets map[string]*domain.Secret
	objects map[string]*domain.Object

	recordS3Err error
	// completeErr fails the database step of CompleteUpload, after finalize.
	completeErr error
	abortCalls  int
}

func newUploadMockRepo() *uploadMockRepo {
	return &uploadMockRepo{
		uploads: make(map[string]*domain.Upload),
		parts:   make(map[string]map[int]domain.UploadPart),
		secrets: make(map[string]*domain.Secret),
		objects: make(map[string]*domain.Object),
	}
}

func (m *uploadMockRepo) StartUpload(_ context.Context, secret *domain.Secret, upload *domain.Upload, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, taken := m.secrets[secret.PublicID]; taken {
		return domain.ErrDuplicate
	}
	m.objects[secret.StorageKey] = &domain.Object{StorageKey: secret.StorageKey, State: domain.ObjectWriting, CreatedAt: now}
	s := *secret
	s.State = domain.SecretUploading
	m.secrets[secret.PublicID] = &s
	m.uploads[upload.SessionID] = &domain.Upload{
		SessionID:       upload.SessionID,
		PublicID:        secret.PublicID,
		UploadTokenHash: upload.UploadTokenHash,
		State:           domain.UploadUploading,
		ExpiresAt:       upload.ExpiresAt,
	}
	return nil
}

func (m *uploadMockRepo) RecordS3UploadID(_ context.Context, storageKey, s3UploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.recordS3Err != nil {
		return m.recordS3Err
	}
	object, ok := m.objects[storageKey]
	if !ok {
		return domain.ErrNotFound
	}
	object.S3UploadID = s3UploadID
	return nil
}

// joined returns the upload with what it needs of its secret and object,
// while the secret has them. The caller holds mu.
func (m *uploadMockRepo) joined(upload *domain.Upload) *domain.Upload {
	u := *upload
	if s, ok := m.secrets[u.PublicID]; ok && u.PublicID != "" {
		u.StorageKey = s.StorageKey
		u.BlobSize = s.BlobSize
		u.SecretExpiresAt = s.ExpiresAt
		if o, ok := m.objects[s.StorageKey]; ok {
			u.S3UploadID = o.S3UploadID
		}
	}
	return &u
}

func (m *uploadMockRepo) partsOf(sessionID string) []domain.UploadPart {
	parts := make([]domain.UploadPart, 0, len(m.parts[sessionID]))
	for _, part := range m.parts[sessionID] {
		parts = append(parts, part)
	}
	return parts
}

func (m *uploadMockRepo) GetUpload(_ context.Context, sessionID string) (*domain.Upload, []domain.UploadPart, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	upload, ok := m.uploads[sessionID]
	if !ok {
		return nil, nil, domain.ErrNotFound
	}
	return m.joined(upload), m.partsOf(sessionID), nil
}

func (m *uploadMockRepo) RecordUploadPart(_ context.Context, part *domain.UploadPart) (*domain.UploadPart, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.parts[part.SessionID] == nil {
		m.parts[part.SessionID] = make(map[int]domain.UploadPart)
	}
	if existing, ok := m.parts[part.SessionID][part.PartNumber]; ok {
		if existing.Offset != part.Offset || existing.Size != part.Size || existing.SHA256 != part.SHA256 {
			return nil, domain.ErrConflict
		}
		return &existing, nil
	}
	copy := *part
	m.parts[part.SessionID][part.PartNumber] = copy
	return &copy, nil
}

func (m *uploadMockRepo) ClearUploadParts(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.parts, sessionID)
	return nil
}

func (m *uploadMockRepo) CompleteUpload(_ context.Context, sessionID string, now time.Time, finalize func(*domain.Upload, []domain.UploadPart) error) (*domain.Upload, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	upload, ok := m.uploads[sessionID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	switch upload.State {
	case domain.UploadCompleted:
		return m.joined(upload), nil
	case domain.UploadUploading:
	default:
		return nil, domain.ErrConflict
	}

	locked := m.joined(upload)
	if err := finalize(locked, m.partsOf(sessionID)); err != nil {
		return nil, err
	}
	// Like a rolled back transaction, a failed database step changes nothing.
	if m.completeErr != nil {
		return nil, m.completeErr
	}
	secret, ok := m.secrets[upload.PublicID]
	if !ok || secret.State != domain.SecretUploading {
		return nil, fmt.Errorf("secret %q of upload %q is not uploading", upload.PublicID, sessionID)
	}
	secret.State = domain.SecretLive
	secret.CreatedAt = &now
	m.objects[secret.StorageKey].State = domain.ObjectStored
	upload.State = domain.UploadCompleted
	upload.FinishedAt = &now
	delete(m.parts, sessionID)
	return m.joined(upload), nil
}

func (m *uploadMockRepo) AbortUpload(_ context.Context, sessionID string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.abortCalls++
	upload, ok := m.uploads[sessionID]
	if !ok {
		return domain.ErrNotFound
	}
	switch upload.State {
	case domain.UploadCompleted:
		return domain.ErrConflict
	case domain.UploadAbandoned:
		return nil
	}

	upload.State = domain.UploadAbandoned
	upload.FinishedAt = &now
	// The secret's row goes, which frees the public id, and its object is
	// doomed for the cleanup to remove.
	if secret, ok := m.secrets[upload.PublicID]; ok && secret.State == domain.SecretUploading {
		delete(m.secrets, upload.PublicID)
		if object, ok := m.objects[secret.StorageKey]; ok {
			object.DoomedAt = &now
		}
	}
	upload.PublicID = ""
	return nil
}

// assertAbandoned checks that an upload was abandoned the whole way: the
// upload ended, its public id is free again and its object is doomed.
func assertAbandoned(t *testing.T, repo *uploadMockRepo, upload *domain.Upload) {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()

	if got := repo.uploads[upload.SessionID].State; got != domain.UploadAbandoned {
		t.Errorf("upload state = %q, want %q", got, domain.UploadAbandoned)
	}
	if _, ok := repo.secrets[upload.PublicID]; ok {
		t.Error("the abandoned upload's secret should be gone, freeing its public id")
	}
	if object := repo.objects[upload.StorageKey]; object == nil || object.DoomedAt == nil {
		t.Error("the abandoned upload's object should be doomed for the cleanup")
	}
}

// uploadMockStore records every call, so a test can tell that the handler
// left storage alone.
type uploadMockStore struct {
	mu             sync.Mutex
	calls          []string
	uploadID       string
	createErr      error
	uploadedParts  map[int][]byte
	completedParts []domain.CompletedPart
	completeCalls  int
	completeErr    error
	deleted        []string
}

func newUploadMockStore() *uploadMockStore {
	return &uploadMockStore{uploadID: "s3-upload-id", uploadedParts: make(map[int][]byte)}
}

func (m *uploadMockStore) record(call string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, call)
}

func (m *uploadMockStore) called(call string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Contains(m.calls, call)
}

func (m *uploadMockStore) GetRange(_ context.Context, _ string, _, _ int64) (io.ReadCloser, error) {
	m.record("GetRange")
	return io.NopCloser(bytes.NewReader(nil)), nil
}
func (m *uploadMockStore) Delete(_ context.Context, key string) error {
	m.record("Delete")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleted = append(m.deleted, key)
	return nil
}
func (m *uploadMockStore) CreateMultipartUpload(_ context.Context, _ string) (string, error) {
	m.record("CreateMultipartUpload")
	if m.createErr != nil {
		return "", m.createErr
	}
	return m.uploadID, nil
}
func (m *uploadMockStore) UploadPart(_ context.Context, _ string, _ string, partNumber int, reader io.Reader, _ int64) (string, error) {
	m.record("UploadPart")
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploadedParts[partNumber] = data
	return fmt.Sprintf("etag-%d", partNumber), nil
}
func (m *uploadMockStore) CompleteMultipartUpload(_ context.Context, _ string, _ string, parts []domain.CompletedPart) error {
	m.record("CompleteMultipartUpload")
	m.mu.Lock()
	defer m.mu.Unlock()
	m.completeCalls++
	if m.completeErr != nil {
		return m.completeErr
	}
	m.completedParts = append([]domain.CompletedPart(nil), parts...)
	return nil
}
func (m *uploadMockStore) AbortMultipartUpload(_ context.Context, _ string, _ string) error {
	m.record("AbortMultipartUpload")
	return nil
}
func (m *uploadMockStore) AbortMultipartUploads(_ context.Context, _ string) error {
	m.record("AbortMultipartUploads")
	return nil
}

func createUploadBody(label string) map[string]any {
	return map[string]any{
		"public_id":       testPublicID(label),
		"metadata_token":  testToken(label + " metadata"),
		"blob_token":      testToken(label + " blob"),
		"deletion_token":  testToken(label + " deletion"),
		"encrypted_meta":  testEncryptedMeta(),
		"expiration":      "1d",
		"burn_after_read": false,
		"blob_size":       10 * 1024 * 1024,
	}
}

func callCreate(t *testing.T, h *UploadHandler, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	c := newEchoContext(createUploadSessionHTTPRequest(t, body), rec)
	callHandler(c, h.CreateUploadSession)
	return rec
}

// createdUpload returns the upload a create answered with, as the repo holds
// it.
func createdUpload(t *testing.T, repo *uploadMockRepo, rec *httptest.ResponseRecorder) *domain.Upload {
	t.Helper()
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	upload, _, err := repo.GetUpload(context.Background(), body.SessionID)
	if err != nil {
		t.Fatalf("get upload %q: %v", body.SessionID, err)
	}
	return upload
}

// onlyUpload returns the single upload the repo holds, with the public id it
// was started for and its object's key, which an abandoned upload no longer
// sees.
func onlyUpload(t *testing.T, repo *uploadMockRepo, publicID string) *domain.Upload {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.uploads) != 1 || len(repo.objects) != 1 {
		t.Fatalf("uploads = %d, objects = %d; want 1 each", len(repo.uploads), len(repo.objects))
	}
	var u domain.Upload
	for _, upload := range repo.uploads {
		u = *upload
	}
	for key := range repo.objects {
		u.StorageKey = key
	}
	u.PublicID = publicID
	return &u
}

func TestUploadSession_CreateSuccess(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callCreate(t, h, createUploadBody("multipart-create"))

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var body struct {
		SessionID   string `json:"session_id"`
		UploadToken string `json:"upload_token"`
		PartSize    int64  `json:"part_size"`
		State       string `json:"state"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.SessionID == "" || body.UploadToken == "" {
		t.Fatal("response missing session credentials")
	}
	if body.PartSize != multipartUploadPartSize {
		t.Errorf("part_size = %d, want %d", body.PartSize, multipartUploadPartSize)
	}
	if body.State != "pending" {
		t.Errorf("state = %q, want %q: clients know an upload under way by that name", body.State, "pending")
	}
	upload := createdUpload(t, repo, rec)
	if want := domain.UploadStorageKey(body.SessionID); upload.StorageKey != want {
		t.Errorf("storage key = %q, want per-session key %q", upload.StorageKey, want)
	}
	if upload.S3UploadID != store.uploadID {
		t.Errorf("s3 upload id = %q, want the recorded %q", upload.S3UploadID, store.uploadID)
	}
	// The secret is on file from the start, but nobody can read it yet.
	secret := repo.secrets[testPublicID("multipart-create")]
	if secret == nil || secret.State != domain.SecretUploading {
		t.Fatalf("secret = %+v, want one in state %q", secret, domain.SecretUploading)
	}
}

func TestUploadSession_CreateRefusesATakenPublicIDBeforeStorage(t *testing.T) {
	for _, state := range []domain.SecretState{domain.SecretUploading, domain.SecretLive, domain.SecretEnded} {
		t.Run(string(state), func(t *testing.T) {
			repo := newUploadMockRepo()
			store := newUploadMockStore()
			h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())
			publicID := testPublicID("multipart-duplicate")
			existing := &domain.Secret{PublicID: publicID, State: state, StorageKey: "someone-else"}
			repo.secrets[publicID] = existing

			rec := callCreate(t, h, createUploadBody("multipart-duplicate"))

			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
			}
			if len(store.calls) != 0 {
				t.Errorf("storage calls = %v, want none for a taken public id", store.calls)
			}
			if repo.secrets[publicID] != existing || len(repo.uploads) != 0 {
				t.Error("the existing secret must be left alone and no upload filed")
			}
		})
	}
}

func TestUploadSession_CreateAbandonsTheUploadWhenStorageFails(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	store.createErr = errors.New("S3 down")
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callCreate(t, h, createUploadBody("multipart-create-s3-down"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	assertAbandoned(t, repo, onlyUpload(t, repo, testPublicID("multipart-create-s3-down")))

	// The public id is free again, so the client can simply retry.
	store.createErr = nil
	if rec := callCreate(t, h, createUploadBody("multipart-create-s3-down")); rec.Code != http.StatusCreated {
		t.Errorf("retry status = %d, want %d. body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
}

func TestUploadSession_CreateAbandonsTheUploadWhenRecordingFails(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	repo.recordS3Err = errors.New("database down")
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callCreate(t, h, createUploadBody("multipart-create-record-fails"))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	assertAbandoned(t, repo, onlyUpload(t, repo, testPublicID("multipart-create-record-fails")))
	// The cleanup finds the multipart upload by its key; the handler does not
	// go back to storage.
	if store.called("AbortMultipartUpload") || store.called("AbortMultipartUploads") || store.called("Delete") {
		t.Errorf("storage calls = %v, want only the create", store.calls)
	}
}

func TestUploadPart_IdempotentAndConflict(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("upload token")
	session := seedUploadSession(repo, uploadToken, 6)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())
	payload := []byte("abcdef")
	hash := sha256HexTest(payload)

	req := uploadPartRequest(session.SessionID, uploadToken, 1, 0, payload, hash)
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("sessionID", "partNumber")
	c.SetParamValues(session.SessionID, "1")
	callHandler(c, h.UploadPart)
	if rec.Code != http.StatusOK {
		t.Fatalf("first upload status = %d, want %d. body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := string(store.uploadedParts[1]); got != string(payload) {
		t.Fatalf("uploaded part = %q, want %q", got, string(payload))
	}

	req = uploadPartRequest(session.SessionID, uploadToken, 1, 0, payload, hash)
	rec = httptest.NewRecorder()
	c = newEchoContext(req, rec)
	c.SetParamNames("sessionID", "partNumber")
	c.SetParamValues(session.SessionID, "1")
	callHandler(c, h.UploadPart)
	if rec.Code != http.StatusOK {
		t.Fatalf("idempotent upload status = %d, want %d. body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	req = uploadPartRequest(session.SessionID, uploadToken, 1, 0, []byte("zzzzzz"), sha256HexTest([]byte("zzzzzz")))
	rec = httptest.NewRecorder()
	c = newEchoContext(req, rec)
	c.SetParamNames("sessionID", "partNumber")
	c.SetParamValues(session.SessionID, "1")
	callHandler(c, h.UploadPart)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestUploadPart_RejectsHashMismatchBeforeS3Upload(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("upload hash mismatch token")
	session := seedUploadSession(repo, uploadToken, 6)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	req := uploadPartRequest(session.SessionID, uploadToken, 1, 0, []byte("abcdef"), sha256HexTest([]byte("zzzzzz")))
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("sessionID", "partNumber")
	c.SetParamValues(session.SessionID, "1")
	callHandler(c, h.UploadPart)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if got := len(store.uploadedParts); got != 0 {
		t.Fatalf("uploaded parts = %d, want 0", got)
	}
}

func TestCompleteUploadSession_FailsWhenPartMissing(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete missing token")
	session := seedUploadSession(repo, uploadToken, s3MinimumPartSize+3)
	repo.parts[session.SessionID] = map[int]domain.UploadPart{
		1: {SessionID: session.SessionID, PartNumber: 1, Offset: 0, Size: s3MinimumPartSize, SHA256: sha256HexTest([]byte("a")), ETag: "etag-1"},
	}
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	req := completeUploadRequest(session.SessionID, uploadToken)
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("sessionID")
	c.SetParamValues(session.SessionID)
	callHandler(c, h.CompleteUploadSession)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if len(store.completedParts) != 0 {
		t.Fatal("S3 complete should not be called for missing parts")
	}
}

func TestCompleteUploadSession_CreatesSecret(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete token")
	session := seedUploadSession(repo, uploadToken, s3MinimumPartSize+3)
	repo.parts[session.SessionID] = map[int]domain.UploadPart{
		1: {SessionID: session.SessionID, PartNumber: 1, Offset: 0, Size: s3MinimumPartSize, SHA256: sha256HexTest([]byte("a")), ETag: "etag-1"},
		2: {SessionID: session.SessionID, PartNumber: 2, Offset: s3MinimumPartSize, Size: 3, SHA256: sha256HexTest([]byte("b")), ETag: "etag-2"},
	}
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	req := completeUploadRequest(session.SessionID, uploadToken)
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("sessionID")
	c.SetParamValues(session.SessionID)
	callHandler(c, h.CompleteUploadSession)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	var body struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if want := session.SecretExpiresAt.UTC().Format(time.RFC3339); body.ExpiresAt != want {
		t.Errorf("expires_at = %q, want the secret's expiry %q", body.ExpiresAt, want)
	}
	secret := repo.secrets[session.PublicID]
	if secret == nil || secret.State != domain.SecretLive || secret.CreatedAt == nil {
		t.Fatalf("secret = %+v, want it live with a creation time", secret)
	}
	if got := repo.objects[session.StorageKey].State; got != domain.ObjectStored {
		t.Errorf("object state = %q, want %q", got, domain.ObjectStored)
	}
	if got := repo.uploads[session.SessionID].State; got != domain.UploadCompleted {
		t.Errorf("upload state = %q, want %q", got, domain.UploadCompleted)
	}
	if got := len(store.completedParts); got != 2 {
		t.Fatalf("completed parts = %d, want 2", got)
	}
}

func TestUploadPart_RejectsPartsOutsideDeclaredBlob(t *testing.T) {
	payload := []byte("abcdef")
	hash := sha256HexTest(payload)
	tests := []struct {
		name       string
		blobSize   int64
		partNumber string
		offset     int64
	}{
		{name: "part number beyond part count", blobSize: 6, partNumber: "2", offset: 0},
		{name: "offset below lower bound for part number", blobSize: 2 * s3MinimumPartSize, partNumber: "2", offset: 0},
		{name: "part overruns blob", blobSize: 4, partNumber: "1", offset: 0},
		{name: "non-final part below minimum size", blobSize: 12, partNumber: "1", offset: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newUploadMockRepo()
			store := newUploadMockStore()
			uploadToken := testToken("bounds " + tt.name)
			session := seedUploadSession(repo, uploadToken, tt.blobSize)
			h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

			req := uploadPartRequest(session.SessionID, uploadToken, 1, tt.offset, payload, hash)
			rec := httptest.NewRecorder()
			c := newEchoContext(req, rec)
			c.SetParamNames("sessionID", "partNumber")
			c.SetParamValues(session.SessionID, tt.partNumber)
			callHandler(c, h.UploadPart)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if len(store.uploadedParts) != 0 {
				t.Fatal("part must be rejected before reaching S3")
			}
		})
	}
}

func TestValidatePartPlacement(t *testing.T) {
	const mib = 1024 * 1024
	tests := []struct {
		name       string
		blobSize   int64
		partNumber int
		offset     int64
		size       int64
		wantErr    bool
	}{
		{name: "single tiny final part", blobSize: 6, partNumber: 1, offset: 0, size: 6},
		{name: "first full part", blobSize: 40 * mib, partNumber: 1, offset: 0, size: 28 * mib},
		{name: "final short part", blobSize: 40 * mib, partNumber: 2, offset: 28 * mib, size: 12 * mib},
		{name: "part number too high", blobSize: 6 * mib, partNumber: 3, offset: 5 * mib, size: mib, wantErr: true},
		{name: "offset too small for part number", blobSize: 40 * mib, partNumber: 3, offset: 6 * mib, size: 5 * mib, wantErr: true},
		{name: "overruns blob", blobSize: 40 * mib, partNumber: 2, offset: 28 * mib, size: 13 * mib, wantErr: true},
		{name: "undersized non-final part", blobSize: 40 * mib, partNumber: 1, offset: 0, size: 4 * mib, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePartPlacement(tt.blobSize, tt.partNumber, tt.offset, tt.size)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validatePartPlacement() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUploadPart_RejectedOnceTheUploadWasAbandoned(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("part after abort token")
	upload := seedUploadSession(repo, uploadToken, 6)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())
	if rec := callAbort(h, upload.SessionID, uploadToken); rec.Code != http.StatusNoContent {
		t.Fatalf("abort status = %d. body: %s", rec.Code, rec.Body.String())
	}

	rec := callUploadPart(h, upload.SessionID, uploadToken, []byte("abcdef"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if len(store.calls) != 0 {
		t.Errorf("storage calls = %v, want none for an abandoned upload", store.calls)
	}
}

func TestUploadPart_RejectedWithoutARecordedMultipartUpload(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("part without s3 id token")
	upload := seedUploadSession(repo, uploadToken, 6)
	// The start failed half-way: storage may know a multipart upload, but the
	// database never learned its id.
	repo.objects[upload.StorageKey].S3UploadID = ""
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callUploadPart(h, upload.SessionID, uploadToken, []byte("abcdef"))

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if len(store.calls) != 0 {
		t.Errorf("storage calls = %v, want none", store.calls)
	}
}

func TestCompleteUploadSession_DBFailureAbandonsTheUpload(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete db failure token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	repo.completeErr = errors.New("database down")
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callComplete(h, upload.SessionID, uploadToken)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	// Storage assembled an object no secret will reference: abandoning dooms
	// it, and the cleanup removes it. The handler itself deletes nothing.
	assertAbandoned(t, repo, upload)
	if len(store.deleted) != 0 {
		t.Errorf("deleted = %v, want no storage delete from the handler", store.deleted)
	}
}

func TestCompleteUploadSession_RepeatedCompleteIsIdempotent(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete twice token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	first := callComplete(h, upload.SessionID, uploadToken)
	second := callComplete(h, upload.SessionID, uploadToken)

	if first.Code != http.StatusCreated || second.Code != http.StatusCreated {
		t.Fatalf("statuses = %d, %d; want both %d. second body: %s", first.Code, second.Code, http.StatusCreated, second.Body.String())
	}
	if first.Body.String() != second.Body.String() {
		t.Errorf("repeated complete answered differently: %s vs %s", first.Body.String(), second.Body.String())
	}
	if store.completeCalls != 1 {
		t.Errorf("storage complete calls = %d, want 1", store.completeCalls)
	}
	if len(store.deleted) != 0 || repo.abortCalls != 0 {
		t.Fatalf("a repeated complete must not touch the live secret: deleted = %v, aborts = %d", store.deleted, repo.abortCalls)
	}
}

func TestCompleteUploadSession_ConcurrentCompletesKeepObject(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete concurrently token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	const requests = 8
	codes := make([]int, requests)
	var wg sync.WaitGroup
	for i := range requests {
		wg.Go(func() {
			codes[i] = callComplete(h, upload.SessionID, uploadToken).Code
		})
	}
	wg.Wait()

	for i, code := range codes {
		if code != http.StatusCreated {
			t.Errorf("request %d status = %d, want %d", i, code, http.StatusCreated)
		}
	}
	if store.completeCalls != 1 {
		t.Errorf("storage complete calls = %d, want 1", store.completeCalls)
	}
	if repo.abortCalls != 0 {
		t.Errorf("abort calls = %d, want none: the object belongs to the live secret", repo.abortCalls)
	}
	if secret := repo.secrets[upload.PublicID]; secret == nil || secret.State != domain.SecretLive {
		t.Fatalf("secret = %+v, want it live", secret)
	}
}

func TestCompleteUploadSession_CompletedUploadWhoseSecretIsGoneConflicts(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete secret gone token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())
	if rec := callComplete(h, upload.SessionID, uploadToken); rec.Code != http.StatusCreated {
		t.Fatalf("first complete status = %d. body: %s", rec.Code, rec.Body.String())
	}
	// The secret expired and the cleanup took its row; the finished upload
	// is still kept for a while.
	delete(repo.secrets, upload.PublicID)

	rec := callComplete(h, upload.SessionID, uploadToken)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if store.completeCalls != 1 {
		t.Errorf("storage complete calls = %d, want 1", store.completeCalls)
	}
}

func TestCompleteUploadSession_AbortedSessionConflicts(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	uploadToken := testToken("complete aborted token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())
	if rec := callAbort(h, upload.SessionID, uploadToken); rec.Code != http.StatusNoContent {
		t.Fatalf("abort status = %d. body: %s", rec.Code, rec.Body.String())
	}

	rec := callComplete(h, upload.SessionID, uploadToken)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if len(store.calls) != 0 {
		t.Fatalf("an abandoned upload must not touch storage: calls = %v", store.calls)
	}
}

func TestCompleteUploadSession_InvalidPartsResetsRecordedParts(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	store.completeErr = fmt.Errorf("wrapped: %w", domain.ErrInvalidParts)
	uploadToken := testToken("complete invalid parts token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callComplete(h, upload.SessionID, uploadToken)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	if len(repo.parts[upload.SessionID]) != 0 {
		t.Fatal("recorded parts should be cleared so the client can re-upload")
	}
	// The client uploads the parts again, so the upload stays under way.
	if got := repo.uploads[upload.SessionID].State; got != domain.UploadUploading || repo.abortCalls != 0 {
		t.Fatalf("upload state = %q, aborts = %d; want it still uploading", got, repo.abortCalls)
	}
}

func TestCompleteUploadSession_UploadGoneAbandonsTheUpload(t *testing.T) {
	repo := newUploadMockRepo()
	store := newUploadMockStore()
	store.completeErr = fmt.Errorf("wrapped: %w", domain.ErrUploadNotFound)
	uploadToken := testToken("complete upload gone token")
	upload := seedSinglePartUploadSession(repo, uploadToken)
	h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

	rec := callComplete(h, upload.SessionID, uploadToken)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	// Storage no longer knows the multipart upload, so this one can never
	// complete; the client starts a new one.
	assertAbandoned(t, repo, upload)
	if len(store.deleted) != 0 {
		t.Errorf("deleted = %v, want no storage delete from the handler", store.deleted)
	}
}

func TestAbortUploadSession(t *testing.T) {
	t.Run("abandons the upload without touching storage", func(t *testing.T) {
		repo := newUploadMockRepo()
		store := newUploadMockStore()
		uploadToken := testToken("abort token")
		upload := seedUploadSession(repo, uploadToken, 6)
		h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

		rec := callAbort(h, upload.SessionID, uploadToken)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
		}
		// The multipart upload goes with the doomed object; the cleanup
		// removes both.
		assertAbandoned(t, repo, upload)
		if len(store.calls) != 0 {
			t.Errorf("storage calls = %v, want none", store.calls)
		}
	})

	t.Run("abort is idempotent", func(t *testing.T) {
		repo := newUploadMockRepo()
		store := newUploadMockStore()
		uploadToken := testToken("abort twice token")
		upload := seedUploadSession(repo, uploadToken, 6)
		h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

		first := callAbort(h, upload.SessionID, uploadToken)
		second := callAbort(h, upload.SessionID, uploadToken)

		if first.Code != http.StatusNoContent || second.Code != http.StatusNoContent {
			t.Fatalf("statuses = %d, %d; want both %d. second body: %s", first.Code, second.Code, http.StatusNoContent, second.Body.String())
		}
		if len(store.calls) != 0 {
			t.Errorf("storage calls = %v, want none", store.calls)
		}
	})

	t.Run("rejects completed session", func(t *testing.T) {
		repo := newUploadMockRepo()
		store := newUploadMockStore()
		uploadToken := testToken("abort completed token")
		upload := seedSinglePartUploadSession(repo, uploadToken)
		h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())
		if rec := callComplete(h, upload.SessionID, uploadToken); rec.Code != http.StatusCreated {
			t.Fatalf("complete status = %d. body: %s", rec.Code, rec.Body.String())
		}

		rec := callAbort(h, upload.SessionID, uploadToken)

		if rec.Code != http.StatusConflict {
			t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusConflict, rec.Body.String())
		}
		if secret := repo.secrets[upload.PublicID]; secret == nil || secret.State != domain.SecretLive {
			t.Fatalf("secret = %+v, want it still live", secret)
		}
	})

	t.Run("rejects wrong upload token", func(t *testing.T) {
		repo := newUploadMockRepo()
		store := newUploadMockStore()
		upload := seedUploadSession(repo, testToken("abort right token"), 6)
		h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

		rec := callAbort(h, upload.SessionID, testToken("abort wrong token"))

		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusForbidden, rec.Body.String())
		}
		if repo.abortCalls != 0 || repo.uploads[upload.SessionID].State != domain.UploadUploading {
			t.Fatal("wrong token must not abort the session")
		}
	})

	t.Run("unknown session is not found", func(t *testing.T) {
		repo := newUploadMockRepo()
		store := newUploadMockStore()
		h := NewUploadHandler(repo, store, 100*1024*1024, testMetrics())

		rec := callAbort(h, testToken("abort unknown session"), testToken("abort unknown token"))

		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
		}
	})
}

func abortUploadRequest(sessionID, uploadToken string) *http.Request {
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/uploads/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+uploadToken)
	return req
}

func callAbort(h *UploadHandler, sessionID, uploadToken string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c := newEchoContext(abortUploadRequest(sessionID, uploadToken), rec)
	c.SetParamNames("sessionID")
	c.SetParamValues(sessionID)
	callHandler(c, h.AbortUploadSession)
	return rec
}

// callUploadPart uploads payload as the first and only part.
func callUploadPart(h *UploadHandler, sessionID, uploadToken string, payload []byte) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c := newEchoContext(uploadPartRequest(sessionID, uploadToken, 1, 0, payload, sha256HexTest(payload)), rec)
	c.SetParamNames("sessionID", "partNumber")
	c.SetParamValues(sessionID, "1")
	callHandler(c, h.UploadPart)
	return rec
}

// seedUploadSession files an upload under way the way StartUpload and
// RecordS3UploadID do, and returns it as GetUpload sees it.
func seedUploadSession(repo *uploadMockRepo, uploadToken string, blobSize int64) *domain.Upload {
	sessionID := testToken("session " + uploadToken)
	now := time.Now()
	secret := &domain.Secret{
		PublicID:          testPublicID("session " + uploadToken),
		StorageKey:        domain.UploadStorageKey(sessionID),
		MetadataTokenHash: tokencrypto.TokenHash(testToken("meta " + uploadToken)),
		BlobTokenHash:     tokencrypto.TokenHash(testToken("blob " + uploadToken)),
		DeletionTokenHash: tokencrypto.TokenHash(testToken("delete " + uploadToken)),
		EncryptedMeta:     testEncryptedMeta(),
		BlobSize:          blobSize,
		ExpiresAt:         now.Add(time.Hour),
	}
	upload := &domain.Upload{
		SessionID:       sessionID,
		UploadTokenHash: tokencrypto.TokenHash(uploadToken),
		ExpiresAt:       now.Add(time.Hour),
	}
	ctx := context.Background()
	if err := repo.StartUpload(ctx, secret, upload, now); err != nil {
		panic(err)
	}
	if err := repo.RecordS3UploadID(ctx, secret.StorageKey, "s3-upload-id"); err != nil {
		panic(err)
	}
	seeded, _, err := repo.GetUpload(ctx, sessionID)
	if err != nil {
		panic(err)
	}
	return seeded
}

func seedSinglePartUploadSession(repo *uploadMockRepo, uploadToken string) *domain.Upload {
	upload := seedUploadSession(repo, uploadToken, 3)
	repo.parts[upload.SessionID] = map[int]domain.UploadPart{
		1: {SessionID: upload.SessionID, PartNumber: 1, Offset: 0, Size: 3, SHA256: sha256HexTest([]byte("a")), ETag: "etag-1"},
	}
	return upload
}

func callComplete(h *UploadHandler, sessionID, uploadToken string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	c := newEchoContext(completeUploadRequest(sessionID, uploadToken), rec)
	c.SetParamNames("sessionID")
	c.SetParamValues(sessionID)
	callHandler(c, h.CompleteUploadSession)
	return rec
}

func createUploadSessionHTTPRequest(t *testing.T, body map[string]any) *http.Request {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func uploadPartRequest(sessionID, uploadToken string, partNumber int, offset int64, payload []byte, hash string) *http.Request {
	req := httptest.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/api/v1/secrets/uploads/%s/parts/%d", sessionID, partNumber),
		bytes.NewReader(payload),
	)
	req.Header.Set("Authorization", "Bearer "+uploadToken)
	req.Header.Set(HeaderPartOffset, strconvFormatInt(offset))
	req.Header.Set(HeaderPartSize, strconvFormatInt(int64(len(payload))))
	req.Header.Set(HeaderPartSHA256, hash)
	return req
}

func completeUploadRequest(sessionID, uploadToken string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads/"+sessionID+"/complete", nil)
	req.Header.Set("Authorization", "Bearer "+uploadToken)
	return req
}

func sha256HexTest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func strconvFormatInt(value int64) string {
	return fmt.Sprintf("%d", value)
}
