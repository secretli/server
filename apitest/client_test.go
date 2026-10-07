// Package apitest checks a running Secretli server through its HTTP API
// alone: uploads, metadata, retrieval, tombstones, deletion and the
// short-code relay, against the real database and object store.
//
// It needs no client and no format library. The server never decrypts
// anything, so random bytes stand in for ciphertext and random tokens for
// the ones a client would derive; only the metadata envelope has to have
// the right shape.
//
// The tests run when SECRETLI_SERVER names the server and skip otherwise:
//
//	SECRETLI_SERVER=http://localhost:8080 go test ./apitest
//
// They send more requests than the rate limits allow from one address, so
// the server under test runs with RATE_LIMIT_MULTIPLIER raised (CI uses
// 100). The real limits are checked by the httpserver package's tests.
package apitest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type api struct {
	t    *testing.T
	base string
}

type reply struct {
	status int
	header http.Header
	body   []byte
}

// server returns the API of the server under test, or skips the test.
func server(t *testing.T) api {
	t.Helper()
	base := strings.TrimRight(os.Getenv("SECRETLI_SERVER"), "/")
	if base == "" {
		t.Skip("set SECRETLI_SERVER to the server under test")
	}
	t.Parallel()
	return api{t: t, base: base}
}

func (a api) do(method, path string, header map[string]string, body []byte) reply {
	a.t.Helper()
	req, err := http.NewRequestWithContext(a.t.Context(), method, a.base+path, bytes.NewReader(body))
	if err != nil {
		a.t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		a.t.Fatalf("%s %s: read body: %v", method, path, err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: data}
}

func (a api) post(path string, header map[string]string, payload any) reply {
	a.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		a.t.Fatal(err)
	}
	return a.do(http.MethodPost, path, header, body)
}

// expect fails the test unless the reply has the status, and decodes its
// JSON body into out when out is set.
func (r reply) expect(t *testing.T, what string, status int, out any) {
	t.Helper()
	if r.status != status {
		t.Fatalf("%s: status %d, want %d; body %s", what, r.status, status, r.body)
	}
	if out != nil {
		if err := json.Unmarshal(r.body, out); err != nil {
			t.Fatalf("%s: decode %s: %v", what, r.body, err)
		}
	}
}

// gone is the body of a 410: what became of a secret, or why a transfer ended.
type gone struct {
	Details map[string]any `json:"details"`
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// secret is what a client would make: random tokens, a metadata envelope
// of the right shape, and random bytes as the encrypted bundle.
type secret struct {
	publicID, metadataToken, blobToken, deletionToken string
	envelope                                          string
	blob                                              []byte
	oneTime                                           bool
}

func newSecret(t *testing.T, size int, oneTime bool) secret {
	t.Helper()
	return secret{
		publicID:      b64(randomBytes(t, 16)),
		metadataToken: b64(randomBytes(t, 32)),
		blobToken:     b64(randomBytes(t, 32)),
		deletionToken: b64(randomBytes(t, 32)),
		envelope:      "v2$" + b64(randomBytes(t, 24)) + "$" + b64(randomBytes(t, 80)),
		blob:          randomBytes(t, size),
		oneTime:       oneTime,
	}
}

type uploadSession struct {
	SessionID   string `json:"session_id"`
	UploadToken string `json:"upload_token"`
	PublicID    string `json:"public_id"`
	PartSize    int64  `json:"part_size"`
	BlobSize    int64  `json:"blob_size"`
}

func (a api) startUpload(s secret) reply {
	a.t.Helper()
	return a.post("/api/v1/secrets/uploads", nil, map[string]any{
		"public_id":       s.publicID,
		"metadata_token":  s.metadataToken,
		"blob_token":      s.blobToken,
		"deletion_token":  s.deletionToken,
		"encrypted_meta":  s.envelope,
		"expiration":      "1h",
		"burn_after_read": s.oneTime,
		"blob_size":       len(s.blob),
	})
}

func (a api) putPart(session uploadSession, number int, offset int, data []byte) reply {
	a.t.Helper()
	return a.putPartWithHash(session, number, offset, data, data)
}

// putPartWithHash sends data but declares the hash of hashed.
func (a api) putPartWithHash(session uploadSession, number int, offset int, data, hashed []byte) reply {
	a.t.Helper()
	sum := sha256.Sum256(hashed)
	header := bearer(session.UploadToken)
	header["Content-Type"] = "application/octet-stream"
	header["X-Part-Offset"] = fmt.Sprint(offset)
	header["X-Part-Size"] = fmt.Sprint(len(data))
	header["X-Part-SHA256"] = hex.EncodeToString(sum[:])
	return a.do(http.MethodPut, fmt.Sprintf("/api/v1/secrets/uploads/%s/parts/%d", session.SessionID, number), header, data)
}

// upload makes the secret through an upload session in parts of the given
// sizes, or in one part.
func (a api) upload(s secret, parts ...int) {
	a.t.Helper()
	if len(parts) == 0 {
		parts = []int{len(s.blob)}
	}
	var session uploadSession
	a.startUpload(s).expect(a.t, "start upload", http.StatusCreated, &session)
	offset := 0
	for i, size := range parts {
		a.putPart(session, i+1, offset, s.blob[offset:offset+size]).expect(a.t, fmt.Sprintf("part %d", i+1), http.StatusOK, nil)
		offset += size
	}
	a.do(http.MethodPost, "/api/v1/secrets/uploads/"+session.SessionID+"/complete", bearer(session.UploadToken), nil).
		expect(a.t, "complete upload", http.StatusCreated, nil)
}

type metadata struct {
	EncryptedMeta string  `json:"encrypted_meta"`
	BlobSize      int64   `json:"blob_size"`
	BurnAfterRead bool    `json:"burn_after_read"`
	ExpiresAt     string  `json:"expires_at"`
	OpenedAt      *string `json:"opened_at"`
}

func (a api) metadata(s secret, token string) reply {
	a.t.Helper()
	return a.do(http.MethodGet, "/api/v1/secrets/"+s.publicID+"/meta", map[string]string{"X-Metadata-Token": token}, nil)
}

type retrievalSession struct {
	SessionToken  string `json:"session_token"`
	BlobSize      int64  `json:"blob_size"`
	BurnAfterRead bool   `json:"burn_after_read"`
}

func (a api) startRetrieval(s secret, blobToken, deletionToken string) reply {
	a.t.Helper()
	header := map[string]string{"X-Blob-Token": blobToken}
	if deletionToken != "" {
		header["X-Deletion-Token"] = deletionToken
	}
	return a.do(http.MethodPost, "/api/v1/secrets/"+s.publicID+"/retrieval-session", header, nil)
}

// readRange reads bytes start to end, both inclusive, and checks them.
func (a api) readRange(s secret, session retrievalSession, start, end int) {
	a.t.Helper()
	header := bearer(session.SessionToken)
	header["Range"] = fmt.Sprintf("bytes=%d-%d", start, end)
	r := a.do(http.MethodGet, "/api/v1/secrets/"+s.publicID+"/blob", header, nil)
	r.expect(a.t, fmt.Sprintf("range %d-%d", start, end), http.StatusPartialContent, nil)
	if want := fmt.Sprintf("bytes %d-%d/%d", start, end, len(s.blob)); r.header.Get("Content-Range") != want {
		a.t.Errorf("Content-Range = %q, want %q", r.header.Get("Content-Range"), want)
	}
	if !bytes.Equal(r.body, s.blob[start:end+1]) {
		a.t.Errorf("range %d-%d: %d bytes back, not the ones uploaded", start, end, len(r.body))
	}
}
