package apitest

import (
	"net/http"
	"os"
	"testing"
	"time"
)

// TestExpiryAndAnUploadLongerThanTheLifetime waits for the shortest lifetime
// to run out, six minutes or so, so it runs only when SECRETLI_SLOW_TESTS is
// set:
//
//	SECRETLI_SLOW_TESTS=1 SECRETLI_SERVER=http://localhost:8080 go test -run Expiry ./apitest
func TestExpiryAndAnUploadLongerThanTheLifetime(t *testing.T) {
	if os.Getenv("SECRETLI_SLOW_TESTS") == "" {
		t.Skip("set SECRETLI_SLOW_TESTS to wait for secrets to expire")
	}
	a := server(t)

	// A secret with five minutes to live, and a one-time one opened at once.
	expiring := newSecret(t, 256, false)
	expiring.expiration = "5m"
	done := a.upload(expiring)
	opened := newSecret(t, 256, true)
	opened.expiration = "5m"
	a.upload(opened)
	a.startRetrieval(opened, opened.blobToken, "").expect(t, "open the one-time secret", http.StatusCreated, nil)

	// An upload of the same lifetime that takes longer than that: the
	// secret's expiry is only provisional until it completes.
	slow := newSecret(t, 256, true)
	slow.expiration = "5m"
	var session uploadSession
	a.startUpload(slow).expect(t, "start the slow upload", http.StatusCreated, &session)
	a.putPart(session, 1, 0, slow.blob).expect(t, "part", http.StatusOK, nil)

	until := done.ExpiresAt
	if session.ExpiresAt.After(until) {
		until = session.ExpiresAt
	}
	select {
	case <-time.After(time.Until(until) + 5*time.Second):
	case <-t.Context().Done():
		t.Fatal("cancelled while waiting for the secrets to expire")
	}

	// Expired: gone for both links, whether the cleanup came by or not.
	a.expectNotThere(expiring, "after it expired")
	a.expectNotThere(opened, "after the opened one expired")

	// Once the cleanup has forgotten them, within a cleanup interval, their
	// ids are free again.
	for _, s := range []secret{expiring, opened} {
		reuse := newSecret(t, 1, false)
		reuse.publicID = s.publicID
		deadline := time.Now().Add(3 * time.Minute)
		for {
			r := a.startUpload(reuse)
			if r.status == http.StatusCreated {
				var freed uploadSession
				r.expect(t, "upload under an expired id", http.StatusCreated, &freed)
				a.abortUpload(freed).expect(t, "abort it", http.StatusNoContent, nil)
				break
			}
			if r.status != http.StatusConflict || time.Now().After(deadline) {
				t.Fatalf("upload under an expired id: status %d; body %s", r.status, r.body)
			}
			select {
			case <-time.After(10 * time.Second):
			case <-t.Context().Done():
				t.Fatal("cancelled while waiting for the cleanup")
			}
		}
	}

	// Completing gives the slow upload's secret its whole lifetime from now.
	before := time.Now()
	var completed completed
	a.completeUpload(session).expect(t, "complete after the provisional expiry", http.StatusCreated, &completed)
	if left := completed.ExpiresAt.Sub(before); left < 5*time.Minute-5*time.Second {
		t.Errorf("the slow upload's secret lives %v from completing, want at least five minutes", left)
	}
	var meta metadata
	a.metadata(slow, slow.metadataToken).expect(t, "metadata of the slow upload's secret", http.StatusOK, &meta)
	if !meta.ExpiresAt.Equal(completed.ExpiresAt) {
		t.Errorf("metadata expires_at = %v, the completed upload said %v", meta.ExpiresAt, completed.ExpiresAt)
	}
	var retrieval retrievalSession
	a.startRetrieval(slow, slow.blobToken, "").expect(t, "open the slow upload's secret", http.StatusCreated, &retrieval)
	a.readRange(slow, retrieval, 0, len(slow.blob)-1)
}
