package apitest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
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

func TestAOneTimeSecretOpensOnceAndItsDownloadCompletes(t *testing.T) {
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
	a.readRange(s, session, 0, 99)

	// Gone for everyone now, with either link, as if it never was.
	a.expectNotThere(s, "after opening")

	// The download that opened it still completes.
	a.readRange(s, session, 100, len(s.blob)-1)
	a.readRange(s, session, 0, len(s.blob)-1)
}

func TestAOneTimeSecretOpenedByItsOwnerIsGoneToo(t *testing.T) {
	a := server(t)
	s := newSecret(t, 512, true)
	a.upload(s)

	// A one-time secret closes whoever opens it.
	var session retrievalSession
	a.startRetrieval(s, s.blobToken, s.deletionToken).expect(t, "owner's retrieval", http.StatusCreated, &session)
	a.expectNotThere(s, "after the owner opened it")
	a.readRange(s, session, 0, len(s.blob)-1)
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

	a.expectNotThere(s, "after deletion")
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

func TestDeletedSecretsAreGoneWhetherOrNotSomeoneOpenedThem(t *testing.T) {
	a := server(t)

	// A one-time secret deleted before anyone opened it.
	oneTime := newSecret(t, 256, true)
	a.upload(oneTime)
	a.deleteSecret(oneTime, oneTime.deletionToken).expect(t, "delete the one-time secret", http.StatusNoContent, nil)
	a.expectNotThere(oneTime, "after deleting the one-time secret")

	// A reusable secret a recipient had opened, then deleted.
	reusable := newSecret(t, 256, false)
	a.upload(reusable)
	a.startRetrieval(reusable, reusable.blobToken, "").expect(t, "recipient's retrieval", http.StatusCreated, nil)
	a.expectOpened(reusable, "after a recipient opened it", true)
	a.deleteSecret(reusable, reusable.deletionToken).expect(t, "delete the opened reusable secret", http.StatusNoContent, nil)
	a.expectNotThere(reusable, "after deleting the opened reusable secret")
}

// TestTimesAreKeptToTheMinute checks the times a secret is told: to the
// minute, the lifetime counted from the completed upload and never shorter
// than chosen, and the same span between creation and expiry for every
// secret of a lifetime, so that they do not tell how long the upload took.
func TestTimesAreKeptToTheMinute(t *testing.T) {
	for expiration, lifetime := range map[string]time.Duration{"5m": 5 * time.Minute, "1h": time.Hour, "7d": 7 * 24 * time.Hour} {
		t.Run(expiration, func(t *testing.T) {
			a := server(t)
			s := newSecret(t, 512, false)
			s.expiration = expiration
			toTheMinute := func(what string, at time.Time) {
				t.Helper()
				if at.IsZero() || !at.Equal(at.Truncate(time.Minute)) {
					t.Errorf("%s = %v, want a time to the minute", what, at)
				}
			}

			var session uploadSession
			a.startUpload(s).expect(t, "start upload", http.StatusCreated, &session)
			toTheMinute("the upload's provisional expires_at", session.ExpiresAt)
			toTheMinute("upload_expires_at", session.UploadExpiresAt)
			a.putPart(session, 1, 0, s.blob).expect(t, "part", http.StatusOK, nil)

			before := time.Now()
			var done completed
			a.completeUpload(session).expect(t, "complete upload", http.StatusCreated, &done)
			var meta metadata
			a.metadata(s, s.metadataToken).expect(t, "metadata", http.StatusOK, &meta)

			toTheMinute("the completed upload's expires_at", done.ExpiresAt)
			toTheMinute("created_at", meta.CreatedAt)
			toTheMinute("expires_at", meta.ExpiresAt)
			if !meta.ExpiresAt.Equal(done.ExpiresAt) {
				t.Errorf("metadata expires_at = %v, the completed upload said %v", meta.ExpiresAt, done.ExpiresAt)
			}
			if span := meta.ExpiresAt.Sub(meta.CreatedAt); span != lifetime+time.Minute {
				t.Errorf("expires_at - created_at = %v, want %v and a minute", span, lifetime)
			}
			// The server's clock is the test's, give or take a little.
			const skew = 5 * time.Second
			if left := done.ExpiresAt.Sub(before); left < lifetime-skew {
				t.Errorf("the secret lives %v from completing, want at least %v", left, lifetime)
			}
			if created := meta.CreatedAt; created.Before(before.Add(-time.Minute-skew)) || created.After(time.Now().Add(skew)) {
				t.Errorf("created_at = %v, want the minute the upload completed in, at about %v", created, before)
			}
		})
	}
}
