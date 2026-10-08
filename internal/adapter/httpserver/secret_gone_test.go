package httpserver

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
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

// decodeGone returns the details of a 410. They tell how the secret ended and
// nothing else, so any other key fails the test.
func decodeGone(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d. body: %s", rec.Code, http.StatusGone, rec.Body.String())
	}
	var body struct {
		Error   string         `json:"error"`
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	keys := slices.Sorted(maps.Keys(body.Details))
	if want := []string{"burn_after_read", "outcome"}; !slices.Equal(keys, want) {
		t.Errorf("details keys = %v, want exactly %v", keys, want)
	}
	return body.Details
}

// assertNothingTold checks for a plain 404 that does not let on whether the
// secret ever existed or how it ended.
func assertNothingTold(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d. body: %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if _, ok := body["details"]; ok {
		t.Errorf("body = %s, want no details", rec.Body.String())
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

func TestSecretMetadata_OpenedOneTimeSecretTellsItWasOpened(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("gone opened")
	token := testToken("gone opened token")
	seedSecret(repo, fs, publicID, token, testToken("gone opened deletion"), true)

	startTestRetrievalSession(t, h, publicID, token)

	details := decodeGone(t, getMetadata(t, h, publicID, token))
	if details["outcome"] != "opened" || details["burn_after_read"] != true {
		t.Errorf("details = %v, want an opened one-time secret", details)
	}
}

func TestSecretMetadata_OwnerOpeningTheirOneTimeSecretEndsItAlike(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("gone owner opened")
	token := testToken("gone owner opened token")
	deletionToken := testToken("gone owner opened deletion")
	seedSecret(repo, fs, publicID, token, deletionToken, true)

	if rec := startSessionAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusCreated {
		t.Fatalf("owner open status = %d, want %d. body: %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	// Nothing tells who opened it: the answer is the same as for a recipient.
	details := decodeGone(t, getMetadata(t, h, publicID, token))
	if details["outcome"] != "opened" || details["burn_after_read"] != true {
		t.Errorf("details = %v, want an opened one-time secret", details)
	}
}

func TestSecretMetadata_DeletedSecretTellsItWasDeleted(t *testing.T) {
	for _, burnAfterRead := range []bool{false, true} {
		repo := newMockRepo()
		fs := newMockFileStore()
		h := NewSecretHandler(repo, fs)
		publicID := testPublicID("gone deleted")
		token := testToken("gone deleted token")
		deletionToken := testToken("gone deleted deletion")
		seedSecret(repo, fs, publicID, token, deletionToken, burnAfterRead)

		if rec := deleteSecretAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusNoContent {
			t.Fatalf("delete status = %d, want %d. body: %s", rec.Code, http.StatusNoContent, rec.Body.String())
		}

		details := decodeGone(t, getMetadata(t, h, publicID, token))
		if details["outcome"] != "deleted" || details["burn_after_read"] != burnAfterRead {
			t.Errorf("details = %v, want deleted with burn_after_read %v", details, burnAfterRead)
		}
	}
}

func TestDeleteSecret_DeletingTwiceTellsItIsGone(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("gone deleted twice")
	token := testToken("gone deleted twice token")
	deletionToken := testToken("gone deleted twice deletion")
	seedSecret(repo, fs, publicID, token, deletionToken, false)

	if rec := deleteSecretAs(t, h, publicID, token, deletionToken); rec.Code != http.StatusNoContent {
		t.Fatalf("first delete status = %d. body: %s", rec.Code, rec.Body.String())
	}

	details := decodeGone(t, deleteSecretAs(t, h, publicID, token, deletionToken))
	if details["outcome"] != "deleted" {
		t.Errorf("details = %v, want deleted", details)
	}
}

func TestSecretMetadata_WhatBecameOfASecretNeedsItsLink(t *testing.T) {
	repo := newMockRepo()
	fs := newMockFileStore()
	h := NewSecretHandler(repo, fs)
	publicID := testPublicID("gone guarded")
	token := testToken("gone guarded token")
	seedSecret(repo, fs, publicID, token, testToken("gone guarded deletion"), true)
	startTestRetrievalSession(t, h, publicID, token)

	rec := getMetadata(t, h, publicID, testToken("somebody else's token"))

	// A guess must learn nothing, not even that the id was ever used.
	assertNothingTold(t, rec)
}

func TestSecretMetadata_ExpiredSecretIsNotFound(t *testing.T) {
	tests := []struct {
		name  string
		state domain.SecretState
	}{
		{name: "live", state: domain.SecretLive},
		{name: "ended", state: domain.SecretEnded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockRepo()
			fs := newMockFileStore()
			h := NewSecretHandler(repo, fs)
			publicID := testPublicID("gone expired " + tt.name)
			token := testToken("gone expired token " + tt.name)
			seedSecret(repo, fs, publicID, token, testToken("gone expired deletion "+tt.name), true)
			// The cleanup has not reached the row yet, but expiry keeps
			// nothing: not even how the secret ended.
			secret := repo.secrets[publicID]
			secret.State = tt.state
			if tt.state == domain.SecretEnded {
				secret.Outcome = domain.OutcomeOpened
			}
			secret.ExpiresAt = time.Now().Add(-time.Minute)

			assertNothingTold(t, getMetadata(t, h, publicID, token))
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
	assertNothingTold(t, getMetadata(t, h, publicID, token))
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
