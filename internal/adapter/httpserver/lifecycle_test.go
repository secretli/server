package httpserver

import (
	"encoding/json"
	"maps"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/secretli/server/internal/domain"
)

// storageLifecycle is the part of an S3 lifecycle configuration that
// deploy/storage-lifecycle.json uses.
type storageLifecycle struct {
	Rules []struct {
		ID     string
		Status string
		Filter struct {
			Prefix string
		}
		Expiration *struct {
			Days int
		}
		AbortIncompleteMultipartUpload *struct {
			DaysAfterInitiation int
		}
	}
}

// The bucket's lifecycle rules are a safety net behind the cleanup, which
// deletes every object itself: they remove what a database restore or a
// bug left behind. They must never take an object the server still needs,
// so they have to outlast the longest a secret's object can live, which
// grows with the lifetimes offered here. Raising a lifetime fails this test
// until the rules are raised too, and then deploy/storage-lifecycle.json
// has to be applied to the bucket again (README, "Storage lifecycle").
func TestStorageLifecycleOutlastsEverySecret(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/storage-lifecycle.json")
	if err != nil {
		t.Fatal(err)
	}
	var lc storageLifecycle
	if err := json.Unmarshal(raw, &lc); err != nil {
		t.Fatal(err)
	}
	const day = 24 * time.Hour
	longest := slices.Max(slices.Collect(maps.Values(expirationDurations)))
	prefix := domain.UploadStorageKey("")

	var expire, abort int
	for _, r := range lc.Rules {
		if r.Status != "Enabled" || r.Filter.Prefix != prefix {
			t.Errorf("rule %s: status %q, prefix %q; want Enabled on %q", r.ID, r.Status, r.Filter.Prefix, prefix)
		}
		if r.Expiration != nil {
			expire = r.Expiration.Days
		}
		if r.AbortIncompleteMultipartUpload != nil {
			abort = r.AbortIncompleteMultipartUpload.DaysAfterInitiation
		}
	}

	// An object is written from the start of its upload, which may take up
	// to uploadSessionTTL, and the secret's lifetime counts from the
	// completed upload. A day on top covers the expiry's minute, the
	// cleanup's lag and a restore that brings a secret back for a while.
	// Storage counts from when the object was made, rounds up to a midnight
	// and acts once a night, so it is only ever later, never earlier.
	if need := longest + uploadSessionTTL + day; time.Duration(expire)*day < need {
		t.Errorf("objects expire after %d days, want at least %v: the longest lifetime %v, an upload of up to %v, and a day", expire, need, longest, uploadSessionTTL)
	}
	// An upload never runs longer than uploadSessionTTL.
	if need := uploadSessionTTL + day; time.Duration(abort)*day < need {
		t.Errorf("unfinished uploads are aborted after %d days, want at least %v", abort, need)
	}
}
