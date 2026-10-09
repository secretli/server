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
	notNullViolation    = "23502"
	foreignKeyViolation = "23503"
)

// insertSecret writes a secrets row straight into the table, bypassing the
// repository, so the schema alone decides whether it is consistent.
const insertSecret = `
	INSERT INTO secrets (public_id, state, storage_key, metadata_token_hash, blob_token_hash, deletion_token_hash,
		encrypted_meta, blob_size, burn_after_read, expires_at, created_at, opened)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

type secretColumns struct {
	state                          string
	storageKey                     *string
	metaHash, blobHash, deleteHash *string
	meta                           *string
	blobSize                       *int64
	burnAfterRead                  bool
	createdAt                      *time.Time
	opened                         bool
}

func ptr[T any](v T) *T { return &v }

// liveColumns is a consistent live secret; each case below breaks one rule.
func liveColumns(storageKey string, now time.Time) secretColumns {
	return secretColumns{
		state:      "live",
		storageKey: ptr(storageKey),
		metaHash:   ptr("m"),
		blobHash:   ptr("b"),
		deleteHash: ptr("d"),
		meta:       ptr("meta"),
		blobSize:   ptr(int64(1)),
		createdAt:  ptr(now),
	}
}

// closing turns columns into an opened one-time secret's: its object, size
// and expiry, and nothing else.
func (c secretColumns) closing() secretColumns {
	c.state, c.burnAfterRead, c.opened = "closing", true, false
	c.metaHash, c.blobHash, c.deleteHash, c.meta, c.createdAt = nil, nil, nil, nil, nil
	return c
}

// execSecret registers the public id, as every upload does first, and
// inserts the secret.
func execSecret(pool *pgxpool.Pool, publicID string, c secretColumns, now time.Time) error {
	if _, err := pool.Exec(context.Background(),
		"INSERT INTO public_ids (public_id, expires_at) VALUES ($1, $2) ON CONFLICT DO NOTHING", publicID, now.Add(time.Hour)); err != nil {
		return err
	}
	_, err := pool.Exec(context.Background(), insertSecret, publicID, c.state, c.storageKey, c.metaHash, c.blobHash, c.deleteHash,
		c.meta, c.blobSize, c.burnAfterRead, now.Add(time.Hour), c.createdAt, c.opened)
	return err
}

func assertPgError(t *testing.T, err error, code, what string) {
	t.Helper()
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || pgErr.Code != code {
		t.Errorf("%s: err = %v, want SQLSTATE %s", what, err, code)
	}
}

// assertViolates checks that err is a check violation of the named
// constraint.
func assertViolates(t *testing.T, err error, constraint, what string) {
	t.Helper()
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || pgErr.Code != checkViolation || pgErr.ConstraintName != constraint {
		t.Errorf("%s: err = %v, want a violation of %s", what, err, constraint)
	}
}

func TestSchema_RefusesInconsistentSecrets(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	now := moment(time.Now())

	for _, key := range []string{"blobs/valid", "blobs/broken"} {
		if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state) VALUES ($1, 'stored')", key); err != nil {
			t.Fatalf("insert object %s: %v", key, err)
		}
	}
	// The template itself is right: a consistent row goes in.
	if err := execSecret(pool, "valid", liveColumns("blobs/valid", now), now); err != nil {
		t.Fatalf("insert a consistent secret: %v", err)
	}

	for _, tc := range []struct {
		name       string
		constraint string
		breakIt    func(c secretColumns) secretColumns
	}{
		{"ended secret", "secrets_known_state", func(c secretColumns) secretColumns {
			c.state, c.createdAt = "ended", nil
			return c
		}},
		{"uploading secret with created_at", "secrets_created_while_live", func(c secretColumns) secretColumns {
			c.state = "uploading"
			return c
		}},
		{"live secret without created_at", "secrets_created_while_live", func(c secretColumns) secretColumns {
			c.createdAt = nil
			return c
		}},
		{"closing secret with created_at", "secrets_created_while_live", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.createdAt = c.createdAt
			return closing
		}},
		{"live secret without its content", "secrets_closing_keeps_only_the_download", func(c secretColumns) secretColumns {
			c.meta = nil
			return c
		}},
		{"live secret without its metadata token", "secrets_closing_keeps_only_the_download", func(c secretColumns) secretColumns {
			c.metaHash = nil
			return c
		}},
		{"closing secret that keeps encrypted_meta", "secrets_closing_keeps_only_the_download", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.meta = c.meta
			return closing
		}},
		{"closing secret that keeps its metadata token", "secrets_closing_keeps_only_the_download", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.metaHash = c.metaHash
			return closing
		}},
		{"closing secret that keeps its deletion token", "secrets_closing_keeps_only_the_download", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.deleteHash = c.deleteHash
			return closing
		}},
		{"closing reusable secret", "secrets_closing_only_one_time", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.burnAfterRead = false
			return closing
		}},
		{"live one-time secret marked opened", "secrets_opened_only_live_reusable", func(c secretColumns) secretColumns {
			c.burnAfterRead, c.opened = true, true
			return c
		}},
		{"closing secret marked opened", "secrets_opened_only_live_reusable", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.opened = true
			return closing
		}},
		{"uploading secret marked opened", "secrets_opened_only_live_reusable", func(c secretColumns) secretColumns {
			c.state, c.createdAt, c.opened = "uploading", nil, true
			return c
		}},
	} {
		c := tc.breakIt(liveColumns("blobs/broken", now))
		assertViolates(t, execSecret(pool, "broken", c, now), tc.constraint, tc.name)
	}

	// Every secret holds its object, and its size: the row goes when the
	// object is doomed.
	for _, tc := range []struct {
		name    string
		breakIt func(c secretColumns) secretColumns
	}{
		{"live secret without its object", func(c secretColumns) secretColumns { c.storageKey = nil; return c }},
		{"closing secret without its object", func(c secretColumns) secretColumns {
			closing := c.closing()
			closing.storageKey = nil
			return closing
		}},
		{"secret without its size", func(c secretColumns) secretColumns { c.blobSize = nil; return c }},
	} {
		assertPgError(t, execSecret(pool, "broken", tc.breakIt(liveColumns("blobs/broken", now)), now), notNullViolation, tc.name)
	}

	// The consistent shapes do go in, so the cases above fail for the rule
	// they break and nothing else. Each takes its own object.
	for _, tc := range []struct {
		name string
		make func(c secretColumns) secretColumns
	}{
		{"an uploading secret", func(c secretColumns) secretColumns { c.state, c.createdAt = "uploading", nil; return c }},
		{"a live one-time secret", func(c secretColumns) secretColumns { c.burnAfterRead = true; return c }},
		{"a reusable secret a recipient opened", func(c secretColumns) secretColumns { c.opened = true; return c }},
		{"an opened one-time secret still downloading", secretColumns.closing},
	} {
		key := "blobs/" + tc.name
		if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state) VALUES ($1, 'stored')", key); err != nil {
			t.Fatalf("insert object %s: %v", key, err)
		}
		if err := execSecret(pool, tc.name, tc.make(liveColumns(key, now)), now); err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestSchema_SecretsAndObjectsReferToEachOther(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	now := moment(time.Now())

	// A secret's object is in the ledger before it is written.
	err := execSecret(pool, "no-object", liveColumns("blobs/unknown", now), now)
	assertPgError(t, err, foreignKeyViolation, "secret pointing at an unknown object")

	// And its id is registered, so that it stays taken after the secret.
	if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state) VALUES ('blobs/unregistered', 'stored')"); err != nil {
		t.Fatalf("insert object: %v", err)
	}
	c := liveColumns("blobs/unregistered", now)
	_, err = pool.Exec(ctx, insertSecret, "unregistered", c.state, c.storageKey, c.metaHash, c.blobHash, c.deleteHash,
		c.meta, c.blobSize, c.burnAfterRead, now.Add(time.Hour), c.createdAt, c.opened)
	assertPgError(t, err, foreignKeyViolation, "secret under an unregistered id")

	if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state) VALUES ('blobs/held', 'stored')"); err != nil {
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

	_, err = pool.Exec(ctx, "INSERT INTO objects (storage_key, state) VALUES ('blobs/odd', 'deleted')")
	assertPgError(t, err, checkViolation, "object in an unknown state")
}

func TestSchema_RefusesInconsistentUploads(t *testing.T) {
	pool := setupTestDB(t)
	ctx := context.Background()
	now := moment(time.Now())

	if _, err := pool.Exec(ctx, "INSERT INTO objects (storage_key, state) VALUES ('blobs/up', 'writing')"); err != nil {
		t.Fatalf("insert object: %v", err)
	}
	uploading := liveColumns("blobs/up", now)
	uploading.state, uploading.createdAt = "uploading", nil
	if err := execSecret(pool, "up", uploading, now); err != nil {
		t.Fatalf("insert uploading secret: %v", err)
	}

	// Only an upload under way keeps the lifetime its secret will get.
	insert := func(sessionID string, publicID *string, state string, finishedAt *time.Time) error {
		lifetime := ptr("1 hour")
		if finishedAt != nil {
			lifetime = nil
		}
		_, err := pool.Exec(ctx, `
			INSERT INTO uploads (session_id, public_id, upload_token_hash, state, expires_at, finished_at, lifetime)
			VALUES ($1, $2, 'u', $3, $4, $5, $6::interval)`, sessionID, publicID, state, now.Add(time.Hour), finishedAt, lifetime)
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
	for _, tc := range []struct {
		name, state string
		finishedAt  *time.Time
		lifetime    *string
	}{
		{"uploading upload without its lifetime", "uploading", nil, nil},
		{"completed upload that keeps its lifetime", "completed", ptr(now), ptr("1 hour")},
	} {
		_, err := pool.Exec(ctx, `
			INSERT INTO uploads (session_id, public_id, upload_token_hash, state, expires_at, finished_at, lifetime)
			VALUES ('broken', 'up', 'u', $1, $2, $3, $4::interval)`, tc.state, now.Add(time.Hour), tc.finishedAt, tc.lifetime)
		assertViolates(t, err, "uploads_lifetime_while_uploading", tc.name)
	}

	// A finished upload may outlive its secret.
	if err := insert("abandoned", nil, "abandoned", ptr(now)); err != nil {
		t.Errorf("an abandoned upload without its secret: %v", err)
	}
}
