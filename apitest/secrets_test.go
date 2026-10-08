package apitest

import (
	"bytes"
	"fmt"
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
	r := a.metadata(s, s.metadataToken)
	r.expect(t, "metadata", http.StatusOK, &meta)
	if meta.EncryptedMeta != s.envelope || meta.BlobSize != int64(len(s.blob)) || !meta.BurnAfterRead {
		t.Errorf("metadata = %+v", meta)
	}
	// Nobody has opened it, and it never tells when anyone did.
	meta.expectOpened(t, "metadata before opening", false)
	if strings.Contains(string(r.body), "opened_at") {
		t.Errorf("metadata tells when the secret was opened: %s", r.body)
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

	// Gone for everyone now; the metadata token still learns what happened, and
	// only that.
	a.startRetrieval(s, s.blobToken, "").expect(t, "second retrieval", http.StatusNotFound, nil)
	var tomb gone
	a.metadata(s, s.metadataToken).expect(t, "metadata after opening", http.StatusGone, &tomb)
	tomb.expectEnded(t, "metadata after opening", "opened", true)

	// Without the token, nothing is told: the same refusal as for a secret that
	// never was.
	guess := a.metadata(s, b64(randomBytes(t, 32)))
	guess.expect(t, "metadata after opening, wrong token", http.StatusNotFound, nil)
	never := a.metadata(newSecret(t, 1, true), b64(randomBytes(t, 32)))
	never.expect(t, "metadata of a secret that never was", http.StatusNotFound, nil)
	if !bytes.Equal(guess.body, never.body) {
		t.Errorf("metadata after opening, wrong token, answers %s; a secret that never was answers %s", guess.body, never.body)
	}
}

func TestAOneTimeSecretOpenedByItsOwnerIsReportedAsOpened(t *testing.T) {
	a := server(t)
	s := newSecret(t, 512, true)
	a.upload(s)

	// A one-time secret ends whoever opens it, and the link is not told who.
	a.startRetrieval(s, s.blobToken, s.deletionToken).expect(t, "owner's retrieval", http.StatusCreated, nil)
	var tomb gone
	a.metadata(s, s.metadataToken).expect(t, "metadata after the owner opened it", http.StatusGone, &tomb)
	tomb.expectEnded(t, "metadata after the owner opened it", "opened", true)
	if _, told := tomb.Details["opened_by_owner"]; told {
		t.Errorf("the owner's opening is told apart from a recipient's: %v", tomb.Details)
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
		a.expectOpened(s, fmt.Sprintf("after opening %d", i+1), true)
	}
}

func TestAReusableSecretTellsWhetherARecipientOpenedIt(t *testing.T) {
	a := server(t)
	s := newSecret(t, 1024, false)
	a.upload(s)

	var meta metadata
	a.metadata(s, s.metadataToken).expect(t, "metadata", http.StatusOK, &meta)
	if meta.EncryptedMeta != s.envelope || meta.BlobSize != int64(len(s.blob)) || meta.BurnAfterRead {
		t.Errorf("metadata = %+v", meta)
	}
	meta.expectOpened(t, "before anyone opened it", false)

	// The owner looking at their own secret does not count, and can read it.
	var ownerSession retrievalSession
	a.startRetrieval(s, s.blobToken, s.deletionToken).expect(t, "owner's retrieval", http.StatusCreated, &ownerSession)
	a.readRange(s, ownerSession, 0, len(s.blob)-1)
	a.expectOpened(s, "after the owner opened it", false)

	// Nor does a refused attempt.
	a.startRetrieval(s, b64(randomBytes(t, 32)), "").expect(t, "retrieval, wrong blob token", http.StatusForbidden, nil)
	a.expectOpened(s, "after a refused attempt", false)

	// A recipient does, and it stays so.
	a.startRetrieval(s, s.blobToken, "").expect(t, "recipient's retrieval", http.StatusCreated, nil)
	a.expectOpened(s, "after a recipient opened it", true)
	a.startRetrieval(s, s.blobToken, s.deletionToken).expect(t, "owner's second retrieval", http.StatusCreated, nil)
	a.expectOpened(s, "after the owner opened it again", true)
}

func TestAWrongDeletionTokenDoesNotMakeARecipientTheOwner(t *testing.T) {
	a := server(t)
	s := newSecret(t, 256, false)
	a.upload(s)

	// A deletion token that is not the secret's own proves nothing, so the
	// opening counts.
	a.startRetrieval(s, s.blobToken, b64(randomBytes(t, 32))).expect(t, "retrieval with a wrong deletion token", http.StatusCreated, nil)
	a.expectOpened(s, "after opening with a wrong deletion token", true)
}

func TestOnlyTheDeletionTokenDeletes(t *testing.T) {
	a := server(t)
	s := newSecret(t, 256, false)
	a.upload(s)

	a.deleteSecret(s, b64(randomBytes(t, 32))).expect(t, "delete, wrong token", http.StatusForbidden, nil)
	a.deleteSecret(s, s.deletionToken).expect(t, "delete", http.StatusNoContent, nil)

	a.startRetrieval(s, s.blobToken, "").expect(t, "retrieval after deletion", http.StatusNotFound, nil)
	var tomb gone
	a.metadata(s, s.metadataToken).expect(t, "metadata after deletion", http.StatusGone, &tomb)
	tomb.expectEnded(t, "metadata after deletion", "deleted", false)
}

func TestDeletingASecretEndsRunningDownloads(t *testing.T) {
	a := server(t)
	s := newSecret(t, 1024, false)
	a.upload(s)
	var session retrievalSession
	a.startRetrieval(s, s.blobToken, "").expect(t, "retrieval", http.StatusCreated, &session)
	a.readRange(s, session, 0, 99)

	a.deleteSecret(s, s.deletionToken).expect(t, "delete", http.StatusNoContent, nil)

	// The session would last a quarter of an hour, but what it reads is gone.
	header := bearer(session.SessionToken)
	header["Range"] = "bytes=0-99"
	a.do(http.MethodGet, "/api/v1/secrets/"+s.publicID+"/blob", header, nil).
		expect(t, "range read after deletion", http.StatusForbidden, nil)
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
	a.abortUpload(session).expect(t, "abort", http.StatusNoContent, nil)
	a.completeUpload(session).expect(t, "complete after abort", http.StatusConflict, nil)
}

func TestASecretIsNotThereUntilItsUploadCompletes(t *testing.T) {
	a := server(t)
	s := newSecret(t, 512, false)
	var session uploadSession
	a.startUpload(s).expect(t, "start upload", http.StatusCreated, &session)

	// An upload under way is nobody's secret yet, not even its owner's.
	notThere := func(when string) {
		t.Helper()
		a.metadata(s, s.metadataToken).expect(t, "metadata "+when, http.StatusNotFound, nil)
		a.startRetrieval(s, s.blobToken, "").expect(t, "retrieval "+when, http.StatusNotFound, nil)
		a.deleteSecret(s, s.deletionToken).expect(t, "delete "+when, http.StatusNotFound, nil)
	}
	notThere("before the first part")
	a.putPart(session, 1, 0, s.blob).expect(t, "part", http.StatusOK, nil)
	notThere("before the upload completes")

	a.completeUpload(session).expect(t, "complete upload", http.StatusCreated, nil)
	var meta metadata
	a.metadata(s, s.metadataToken).expect(t, "metadata after the upload completed", http.StatusOK, &meta)
	if meta.EncryptedMeta != s.envelope {
		t.Errorf("metadata = %+v", meta)
	}
}

func TestAnAbandonedUploadFreesItsPublicID(t *testing.T) {
	a := server(t)
	s := newSecret(t, 512, false)
	var abandoned uploadSession
	a.startUpload(s).expect(t, "start upload", http.StatusCreated, &abandoned)
	a.putPart(abandoned, 1, 0, s.blob).expect(t, "part", http.StatusOK, nil)
	a.abortUpload(abandoned).expect(t, "abort", http.StatusNoContent, nil)
	a.abortUpload(abandoned).expect(t, "abort again", http.StatusNoContent, nil)

	// Nothing of the secret is left, and its public id can be used again.
	a.metadata(s, s.metadataToken).expect(t, "metadata after the abort", http.StatusNotFound, nil)
	a.upload(s)

	// The abandoned session still cannot make anything, nor undo the new secret.
	a.completeUpload(abandoned).expect(t, "complete the abandoned upload", http.StatusConflict, nil)
	var meta metadata
	a.metadata(s, s.metadataToken).expect(t, "metadata of the second upload", http.StatusOK, &meta)
	if meta.EncryptedMeta != s.envelope {
		t.Errorf("metadata = %+v", meta)
	}
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
