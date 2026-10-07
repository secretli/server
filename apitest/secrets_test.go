package apitest

import (
	"net/http"
	"strings"
	"testing"
)

func TestHealthAndVersion(t *testing.T) {
	a := server(t)
	a.do(http.MethodGet, "/api/v1/health/live", nil, nil).expect(t, "liveness", http.StatusOK, nil)
	a.do(http.MethodGet, "/api/v1/health/ready", nil, nil).expect(t, "readiness", http.StatusOK, nil)
	var version struct {
		Version string `json:"version"`
	}
	a.do(http.MethodGet, "/api/v1/version", nil, nil).expect(t, "version", http.StatusOK, &version)
	if version.Version == "" {
		t.Error("the version is empty")
	}
}

func TestAOneTimeSecretOpensOnceAndLeavesATombstone(t *testing.T) {
	a := server(t)
	s := newSecret(t, 4096, true)
	a.upload(s)

	// The metadata needs the metadata token, and hands the envelope back as it was.
	a.metadata(s, b64(randomBytes(t, 32))).expect(t, "metadata, wrong token", http.StatusForbidden, nil)
	var meta metadata
	a.metadata(s, s.metadataToken).expect(t, "metadata", http.StatusOK, &meta)
	if meta.EncryptedMeta != s.envelope || meta.BlobSize != int64(len(s.blob)) || !meta.BurnAfterRead || meta.OpenedAt != nil {
		t.Errorf("metadata = %+v", meta)
	}

	// Reading needs the blob token; starting the session is what uses the secret up.
	a.startRetrieval(s, b64(randomBytes(t, 32)), "").expect(t, "retrieval, wrong token", http.StatusForbidden, nil)
	var session retrievalSession
	a.startRetrieval(s, s.blobToken, "").expect(t, "retrieval", http.StatusCreated, &session)
	if session.BlobSize != int64(len(s.blob)) || !session.BurnAfterRead {
		t.Errorf("session = %+v", session)
	}
	a.readRange(s, session, 0, len(s.blob)-1)
	a.readRange(s, session, 100, 199)

	// Gone for everyone now; the metadata token still learns what happened.
	a.startRetrieval(s, s.blobToken, "").expect(t, "second retrieval", http.StatusNotFound, nil)
	var tomb gone
	a.metadata(s, s.metadataToken).expect(t, "metadata after opening", http.StatusGone, &tomb)
	if tomb.Details["outcome"] != "opened" || tomb.Details["burn_after_read"] != true || tomb.Details["opened_by_owner"] != false {
		t.Errorf("tombstone = %v", tomb.Details)
	}
	// Without the token, nothing is told: a refusal (403 until cleanup
	// removes the row, 404 after), never the story.
	r := a.metadata(s, b64(randomBytes(t, 32)))
	if r.status != http.StatusForbidden && r.status != http.StatusNotFound {
		t.Errorf("metadata after opening, wrong token: status %d, want 403 or 404; body %s", r.status, r.body)
	}
	if strings.Contains(string(r.body), "outcome") {
		t.Errorf("metadata after opening, wrong token, told what happened: %s", r.body)
	}
}

func TestTheOwnerOpeningAOneTimeSecretIsRecorded(t *testing.T) {
	a := server(t)
	s := newSecret(t, 512, true)
	a.upload(s)

	a.startRetrieval(s, s.blobToken, s.deletionToken).expect(t, "owner's retrieval", http.StatusCreated, nil)
	var tomb gone
	a.metadata(s, s.metadataToken).expect(t, "metadata after the owner opened it", http.StatusGone, &tomb)
	if tomb.Details["outcome"] != "opened" || tomb.Details["opened_by_owner"] != true {
		t.Errorf("tombstone = %v", tomb.Details)
	}
}

func TestAReusableSecretInSeveralPartsOpensAgain(t *testing.T) {
	a := server(t)
	const mib = 1 << 20
	s := newSecret(t, 6*mib+123, false)
	// Every part but the last must be at least 5 MiB.
	a.upload(s, 5*mib, mib+123)

	for i := range 2 {
		var session retrievalSession
		a.startRetrieval(s, s.blobToken, "").expect(t, "retrieval", http.StatusCreated, &session)
		a.readRange(s, session, 0, len(s.blob)-1)
		a.readRange(s, session, 5*mib-10, 5*mib+10) // across the part boundary
		var meta metadata
		a.metadata(s, s.metadataToken).expect(t, "metadata", http.StatusOK, &meta)
		if meta.OpenedAt == nil {
			t.Errorf("opening %d: opened_at is not set", i+1)
		}
	}
}

func TestOnlyTheDeletionTokenDeletes(t *testing.T) {
	a := server(t)
	s := newSecret(t, 256, false)
	a.upload(s)

	del := func(deletionToken string) reply {
		return a.do(http.MethodDelete, "/api/v1/secrets/"+s.publicID, map[string]string{
			"X-Metadata-Token": s.metadataToken,
			"X-Deletion-Token": deletionToken,
		}, nil)
	}
	del(b64(randomBytes(t, 32))).expect(t, "delete, wrong token", http.StatusForbidden, nil)
	del(s.deletionToken).expect(t, "delete", http.StatusNoContent, nil)

	a.startRetrieval(s, s.blobToken, "").expect(t, "retrieval after deletion", http.StatusNotFound, nil)
	var tomb gone
	a.metadata(s, s.metadataToken).expect(t, "metadata after deletion", http.StatusGone, &tomb)
	if tomb.Details["outcome"] != "deleted" {
		t.Errorf("tombstone = %v", tomb.Details)
	}
}

func TestUploadRules(t *testing.T) {
	a := server(t)
	s := newSecret(t, 1024, false)
	var session uploadSession
	a.startUpload(s).expect(t, "start upload", http.StatusCreated, &session)
	a.startUpload(s).expect(t, "the same public id again", http.StatusConflict, nil)

	// A part has to match its declared hash.
	part := s.blob
	tampered := append([]byte{}, part...)
	tampered[0] ^= 1
	a.putPartWithHash(session, 1, 0, tampered, part).expect(t, "part with a wrong hash", http.StatusBadRequest, nil)

	// Repeating a part with the same bytes is safe; other bytes are refused.
	a.putPart(session, 1, 0, part).expect(t, "part", http.StatusOK, nil)
	a.putPart(session, 1, 0, part).expect(t, "the same part again", http.StatusOK, nil)
	a.putPart(session, 1, 0, tampered).expect(t, "the part with other bytes", http.StatusConflict, nil)

	// The upload token is checked.
	other := session
	other.UploadToken = b64(randomBytes(t, 32))
	a.putPart(other, 1, 0, part).expect(t, "part with a wrong upload token", http.StatusForbidden, nil)

	// An abandoned upload cannot be completed afterwards.
	a.do(http.MethodDelete, "/api/v1/secrets/uploads/"+session.SessionID, bearer(session.UploadToken), nil).
		expect(t, "abort", http.StatusNoContent, nil)
	a.do(http.MethodPost, "/api/v1/secrets/uploads/"+session.SessionID+"/complete", bearer(session.UploadToken), nil).
		expect(t, "complete after abort", http.StatusConflict, nil)
}

func TestMalformedRequestsAreRefused(t *testing.T) {
	a := server(t)
	a.do(http.MethodPost, "/api/v1/secrets/uploads", nil, []byte("{not json")).expect(t, "upload, not JSON", http.StatusBadRequest, nil)
	s := newSecret(t, 16, false)
	s.envelope = "v1$whatever"
	a.startUpload(s).expect(t, "upload, wrong envelope", http.StatusBadRequest, nil)
	a.do(http.MethodGet, "/api/v1/secrets/not-an-id/meta", map[string]string{"X-Metadata-Token": b64(randomBytes(t, 32))}, nil).
		expect(t, "metadata, malformed id", http.StatusBadRequest, nil)
}
