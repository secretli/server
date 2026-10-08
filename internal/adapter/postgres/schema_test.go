package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	checkViolation      = "23514"
	foreignKeyViolation = "23503"
)

// insertSecret writes a secrets row straight into the table, bypassing the
// repository, so the schema alone decides whether it is consistent.
const insertSecret = `
	INSERT INTO secrets (public_id, state, storage_key, metadata_token_hash, blob_token_hash, deletion_token_hash,
		encrypted_meta, blob_size, burn_after_read, expires_at, created_at, opened, outcome)
	VALUES ($1, $2, $3, 'm', $4, $5, $6, 1, $7, $8, $9, $10, $11)`

type secretColumns struct {
	state                string
	storageKey           *string
	blobHash, deleteHash *string
	meta                 *string
	burnAfterRead        bool
	createdAt            *time.Time
	opened               bool
	outcome              *string
}

func ptr[T any](v T) *T { return &v }

// liveColumns is a consistent live secret; each case below breaks one rule.
func liveColumns(storageKey string, now time.Time) secretColumns {
	return secretColumns{
		state:      "live",
		storageKey: ptr(storageKey),
		blobHash:   ptr("b"),
		deleteHash: ptr("d"),
		meta:       ptr("meta"),
		createdAt:  ptr(now),
	}
}

func execSecret(pool *pgxpool.Pool, publicID string, c secretColumns, now time.Time) error {
	_, err := pool.Exec(context.Background(), insertSecret, publicID, c.state, c.storageKey, c.blobHash, c.deleteHash,
		c.meta, c.burnAfterRead, now.Add(time.Hour), c.createdAt, c.opened, c.outcome)
	return err
}

func assertPgError(t *testing.T, err error, code, what string) {
	t.Helper()
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || pgErr.Code != code {
		t.Errorf("%s: err = %v, want SQLSTATE %s", what, err, code)
	}
}

func TestSchema_RefusesInconsistentSecrets(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	now := moment(time.Now())

	for _, key := range []string{"blobs/valid", "blobs/broken"} {
		if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state, created_at) VALUES ($1, 'stored', $2)", key, now); err != nil {
			t.Fatalf("insert object %s: %v", key, err)
		}
	}
	// The template itself is right: a consistent row goes in.
	if err := execSecret(pool, "valid", liveColumns("blobs/valid", now), now); err != nil {
		t.Fatalf("insert a consistent secret: %v", err)
	}

	for _, tc := range []struct {
		name    string
		breakIt func(c *secretColumns)
	}{
		{"unknown state", func(c *secretColumns) { c.state = "expired" }},
		{"uploading secret with created_at", func(c *secretColumns) { c.state = "uploading" }},
		{"live secret without created_at", func(c *secretColumns) { c.createdAt = nil }},
		{"live secret with an outcome", func(c *secretColumns) { c.outcome = ptr("opened") }},
		{"live secret without its object", func(c *secretColumns) { c.storageKey = nil }},
		{"live secret without its content", func(c *secretColumns) { c.meta = nil }},
		{"live secret without its blob token", func(c *secretColumns) { c.blobHash = nil }},
		{"ended secret without an outcome", func(c *secretColumns) {
			c.state, c.meta, c.blobHash, c.deleteHash = "ended", nil, nil, nil
		}},
		{"unknown outcome", func(c *secretColumns) {
			c.state, c.outcome, c.meta, c.blobHash, c.deleteHash = "ended", ptr("expired"), nil, nil, nil
		}},
		{"ended secret that keeps encrypted_meta", func(c *secretColumns) {
			c.state, c.outcome, c.blobHash, c.deleteHash = "ended", ptr("opened"), nil, nil
		}},
		{"ended secret that keeps its deletion token", func(c *secretColumns) {
			c.state, c.outcome, c.meta, c.blobHash = "ended", ptr("opened"), nil, nil
		}},
		{"deleted secret that keeps its object", func(c *secretColumns) {
			c.state, c.outcome, c.meta, c.blobHash, c.deleteHash = "ended", ptr("deleted"), nil, nil, nil
		}},
		{"one-time secret marked opened", func(c *secretColumns) { c.burnAfterRead, c.opened = true, true }},
	} {
		c := liveColumns("blobs/broken", now)
		tc.breakIt(&c)
		assertPgError(t, execSecret(pool, "broken", c, now), checkViolation, tc.name)
	}

	// The consistent ended shapes do go in, so the cases above fail for the
	// rule they break and nothing else.
	opened := liveColumns("blobs/broken", now)
	opened.state, opened.outcome, opened.meta, opened.blobHash, opened.deleteHash = "ended", ptr("opened"), nil, nil, nil
	if err := execSecret(pool, "ended-opened", opened, now); err != nil {
		t.Errorf("an opened secret still draining: %v", err)
	}
	deleted := opened
	deleted.outcome, deleted.storageKey = ptr("deleted"), nil
	if err := execSecret(pool, "ended-deleted", deleted, now); err != nil {
		t.Errorf("a deleted secret: %v", err)
	}
}

func TestSchema_SecretsAndObjectsReferToEachOther(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	now := moment(time.Now())

	// A secret's object is in the ledger before it is written.
	err := execSecret(pool, "no-object", liveColumns("blobs/unknown", now), now)
	assertPgError(t, err, foreignKeyViolation, "secret pointing at an unknown object")

	if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state, created_at) VALUES ('blobs/held', 'stored', $1)", now); err != nil {
		t.Fatalf("insert object: %v", err)
	}
	if err := execSecret(pool, "holder", liveColumns("blobs/held", now), now); err != nil {
		t.Fatalf("insert secret: %v", err)
	}
	// An object a secret holds cannot be forgotten.
	_, err = pool.Exec(ctx, "DELETE FROM objects WHERE storage_key = 'blobs/held'")
	assertPgError(t, err, foreignKeyViolation, "deleting an object a secret holds")
	// And no two secrets share one.
	err = execSecret(pool, "second-holder", liveColumns("blobs/held", now), now)
	assertPgError(t, err, "23505", "two secrets on one object")

	_, err = pool.Exec(ctx, "INSERT INTO objects (storage_key, state, created_at) VALUES ('blobs/odd', 'deleted', $1)", now)
	assertPgError(t, err, checkViolation, "object in an unknown state")
}

func TestSchema_RefusesInconsistentUploads(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	now := moment(time.Now())

	if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state, created_at) VALUES ('blobs/up', 'writing', $1)", now); err != nil {
		t.Fatalf("insert object: %v", err)
	}
	uploading := secretColumns{state: "uploading", storageKey: ptr("blobs/up"), blobHash: ptr("b"), deleteHash: ptr("d"), meta: ptr("meta")}
	if err := execSecret(pool, "up", uploading, now); err != nil {
		t.Fatalf("insert uploading secret: %v", err)
	}

	insert := func(sessionID string, publicID *string, state string, finishedAt *time.Time) error {
		_, err := pool.Exec(ctx, `
			INSERT INTO uploads (session_id, public_id, upload_token_hash, state, expires_at, finished_at)
			VALUES ($1, $2, 'u', $3, $4, $5)`, sessionID, publicID, state, now.Add(time.Hour), finishedAt)
		return err
	}
	if err := insert("valid", ptr("up"), "uploading", nil); err != nil {
		t.Fatalf("insert a consistent upload: %v", err)
	}

	for _, tc := range []struct {
		name       string
		publicID   *string
		state      string
		finishedAt *time.Time
		code       string
	}{
		{"uploading upload without its secret", nil, "uploading", nil, checkViolation},
		{"uploading upload with finished_at", ptr("up"), "uploading", ptr(now), checkViolation},
		{"completed upload without finished_at", ptr("up"), "completed", nil, checkViolation},
		{"abandoned upload without finished_at", nil, "abandoned", nil, checkViolation},
		{"unknown state", ptr("up"), "pending", nil, checkViolation},
		{"upload of an unknown secret", ptr("unknown"), "uploading", nil, foreignKeyViolation},
	} {
		assertPgError(t, insert("broken", tc.publicID, tc.state, tc.finishedAt), tc.code, tc.name)
	}

	// A finished upload may outlive its secret.
	if err := insert("abandoned", nil, "abandoned", ptr(now)); err != nil {
		t.Errorf("an abandoned upload without its secret: %v", err)
	}
}
