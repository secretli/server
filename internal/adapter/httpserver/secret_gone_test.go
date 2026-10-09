package httpserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/secretli/server/internal/domain"
)

func getMetadata(t *testing.T, h *SecretHandler, publicID, metadataToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/secrets/"+publicID+"/meta", nil)
	req.Header.Set(HeaderMetadataToken, metadataToken)
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("publicID")
	c.SetParamValues(publicID)
	callHandler(c, h.SecretMetadata)
	return rec
}

// assertNothingTold checks for a plain 404 that does not let on whether the
// secret ever existed or what became of it.
func assertNothingTold(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusNotFound {
		t.Errorf("%s: status = %d, want %d. body: %s", what, rec.Code, http.StatusNotFound, rec.Body.String())
		return
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: decode body: %v", what, err)
	}
	if _, ok := body["details"]; ok {
		t.Errorf("%s: body = %s, want no details", what, rec.Body.String())
	}
}

func decodeMetadata(t *testing.T, rec *httptest.ResponseRecorder) domain.SecretMetadataResponse {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body domain.SecretMetadataResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return body
}

// startSessionAs opens a secret as a recipient, or as the owner when the
// deletion token is given.
func startSessionAs(t *testing.T, h *SecretHandler, publicID, blobToken, deletionToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/"+publicID+"/retrieval-session", nil)
	req.Header.Set(HeaderBlobToken, blobToken)
	if deletionToken != "" {
		req.Header.Set(HeaderDeletionToken, deletionToken)
	}
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("publicID")
	c.SetParamValues(publicID)
	callHandler(c, h.StartRetrievalSession)
	return rec
}

func deleteSecretAs(t *testing.T, h *SecretHandler, publicID, metadataToken, deletionToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/"+publicID, nil)
	req.Header.Set(HeaderMetadataToken, metadataToken)
	req.Header.Set(HeaderDeletionToken, deletionToken)
	rec := httptest.NewRecorder()
	c := newEchoContext(req, rec)
	c.SetParamNames("publicID")
	c.SetParamValues(publicID)
	callHandler(c, h.DeleteSecret)
	return rec
}

// TestGoneSecretsAreAnsweredLikeSecretsThatNeverWere ends a secret in each
// way there is, then asks with both its links. Nothing tells how it ended,
// or that it existed: every answer is the 404 a secret that never was gets.
func TestGoneSecretsAreAnsweredLikeSecretsThatNeverWere(t *testing.T) {
	for _, tc := range []struct {
		name          string
		burnAfterRead bool
		end           func(t *testing.T, h *SecretHandler, repo *mockSecretRepo, publicID, token, deletionToken string)
	}{
		{"one-time secret opened by a recipient", true, func(t *testing.T, h *SecretHandler, _ *mockSecretRepo, publicID, token, _ string) {
			startTestRetrievalSession(t, h, publicID, token)
		}},
		{"one-time secret opened by its owner", true, func(t *testing.T, h *SecretHandler, _ *mockSecretRepo, publicID, token, deletionToken string) {
			if rec := startSessionAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusCreated {
				t.Fatalf("owner's open: status %d. body: %s", rec.Code, rec.Body.String())
			}
		}},
		{"deleted one-time secret", true, func(t *testing.T, h *SecretHandler, _ *mockSecretRepo, publicID, token, deletionToken string) {
			if rec := deleteSecretAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusNoContent {
				t.Fatalf("delete: status %d. body: %s", rec.Code, rec.Body.String())
			}
		}},
		{"reusable secret opened, then deleted", false, func(t *testing.T, h *SecretHandler, _ *mockSecretRepo, publicID, token, deletionToken string) {
			startTestRetrievalSession(t, h, publicID, token)
			if rec := deleteSecretAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusNoContent {
				t.Fatalf("delete: status %d. body: %s", rec.Code, rec.Body.String())
			}
		}},
		// The cleanup has not reached the row yet, but expiry keeps nothing.
		{"expired secret", false, func(_ *testing.T, _ *SecretHandler, repo *mockSecretRepo, publicID, _, _ string) {
			repo.secrets[publicID].ExpiresAt = time.Now().Add(-time.Minute)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newMockRepo()
			fs := newMockFileStore()
			h := NewSecretHandler(repo, fs)
			publicID := testPublicID("gone " + tc.name)
			token := testToken("gone token " + tc.name)
			deletionToken := testToken("gone deletion " + tc.name)
			seedSecret(repo, fs, publicID, token, deletionToken, tc.burnAfterRead)
			tc.end(t, h, repo, publicID, token, deletionToken)

			never := getMetadata(t, h, testPublicID("never "+tc.name), token)
			meta := getMetadata(t, h, publicID, token)
			assertNothingTold(t, meta, "metadata")
			if !bytes.Equal(meta.Body.Bytes(), never.Body.Bytes()) {
				t.Errorf("metadata answers %s; a secret that never was answers %s", meta.Body.String(), never.Body.String())
			}
			assertNothingTold(t, getMetadata(t, h, publicID, testToken("somebody else's token")), "metadata, wrong token")
			assertNothingTold(t, startSessionAs(t, h, publicID, token, ""), "open")
			assertNothingTold(t, startSessionAs(t, h, publicID, token, deletionToken), "open with the owner link")
			assertNothingTold(t, deleteSecretAs(t, h, publicID, token, deletionToken), "delete")
		})
	}
}

func TestSecretMetadata_UploadingSecretIsNotFound(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("gone uploading")
	token := testToken("gone uploading token")
	seedSecret(repo, fs, publicID, token, testToken("gone uploading deletion"), false)
	repo.secrets[publicID].State = domain.SecretUploading
	repo.secrets[publicID].CreatedAt = nil

	// Until the upload completes, the secret does not exist for anybody.
	assertNothingTold(t, getMetadata(t, h, publicID, token), "metadata")
}

func TestSecretMetadata_ReusableSecretTellsWhetherARecipientOpenedIt(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("reusable opened")
	token := testToken("reusable opened token")
	deletionToken := testToken("reusable opened deletion")
	seedSecret(repo, fs, publicID, token, deletionToken, false)

	// The owner looking at their own secret does not count.
	if rec := startSessionAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusCreated {
		t.Fatalf("owner open status = %d. body: %s", rec.Code, rec.Body.String())
	}
	if meta := decodeMetadata(t, getMetadata(t, h, publicID, token)); meta.Opened {
		t.Error("opened = true after the owner's own look, want false")
	}

	startTestRetrievalSession(t, h, publicID, token)
	if meta := decodeMetadata(t, getMetadata(t, h, publicID, token)); !meta.Opened {
		t.Error("opened = false after a recipient opened the secret, want true")
	}
}

func TestStartRetrievalSession_MalformedDeletionTokenIsRejected(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("malformed deletion")
	token := testToken("malformed deletion token")
	seedSecret(repo, fs, publicID, token, testToken("malformed deletion deletion"), false)

	rec := startSessionAs(t, h, publicID, token, "not a token")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
