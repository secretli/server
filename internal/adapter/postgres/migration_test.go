package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"
)

// migrationDatabase creates an empty database next to the test database and
// returns a connection to it and a migrator with every migration loaded.
func migrationDatabase(t *testing.T) (*pgx.Conn, *migrate.Migrator) {
	t.Helper()
	pool := setupTestDB(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, "DROP DATABASE IF EXISTS secretli_migration_test"); err != nil {
		t.Fatalf("drop database: %v", err)
	}
	if _, err := pool.Exec(ctx, "CREATE DATABASE secretli_migration_test"); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP DATABASE IF EXISTS secretli_migration_test WITH (FORCE)")
	})

	connString := strings.Replace(pool.Config().ConnString(), "/secretli_test", "/secretli_migration_test", 1)
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	migrator, err := migrate.NewMigrator(ctx, conn, "schema_version")
	if err != nil {
		t.Fatalf("create migrator: %v", err)
	}
	if err := migrator.LoadMigrations(os.DirFS("migrations")); err != nil {
		t.Fatalf("load migrations: %v", err)
	}
	return conn, migrator
}

// TestMigration_AppliesRollsBackAndAppliesAgain migrates an empty database to
// the schema, all the way back down and up again.
func TestMigration_AppliesRollsBackAndAppliesAgain(t *testing.T) {
	conn, migrator := migrationDatabase(t)
	ctx := context.Background()
	tables := []string{"objects", "secrets", "uploads", "upload_parts", "retrieval_sessions", "code_transfers"}
	exists := func(kind, name string) bool {
		t.Helper()
		var found bool
		if err := conn.QueryRow(ctx, "SELECT to_"+kind+"($1) IS NOT NULL", name).Scan(&found); err != nil {
			t.Fatalf("look up %s: %v", name, err)
		}
		return found
	}
	assertSchema := func(want bool, after string) {
		t.Helper()
		for _, table := range tables {
			if exists("regclass", table) != want {
				t.Errorf("after %s: table %s exists = %v, want %v", after, table, !want, want)
			}
		}
		// The trigger's function is dropped on its own, not with its table.
		if exists("regproc", "notify_transfer_event") != want {
			t.Errorf("after %s: notify_transfer_event exists = %v, want %v", after, !want, want)
		}
	}

	if err := migrator.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	version, err := migrator.GetCurrentVersion(ctx)
	if err != nil {
		t.Fatalf("current version: %v", err)
	}
	if version != 4 {
		t.Errorf("version = %d, want every migration", version)
	}
	assertSchema(true, "migrating up")

	if err := migrator.MigrateTo(ctx, 0); err != nil {
		t.Fatalf("migrate down to 0: %v", err)
	}
	assertSchema(false, "rolling back")

	if err := migrator.Migrate(ctx); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
	assertSchema(true, "migrating up again")
}

// v3Secret is a secrets row as schema version 3 holds it.
type v3Secret struct {
	id, state             string
	storageKey            *string
	blobSize              int64
	burnAfterRead, opened bool
	createdAt             *time.Time
	outcome               *string
}

// v4Secret is what migration 004 is about in a secrets row.
type v4Secret struct {
	state            string
	storageKey       string
	blobSize         int64
	createdAt        *time.Time
	hasTokens        bool
	opened           bool
	expiresAt        time.Time
	retrievalSession bool
}

func (s v4Secret) equal(o v4Secret) bool {
	return s.state == o.state && s.storageKey == o.storageKey && s.blobSize == o.blobSize &&
		(s.createdAt == nil) == (o.createdAt == nil) && (s.createdAt == nil || s.createdAt.Equal(*o.createdAt)) &&
		s.hasTokens == o.hasTokens && s.opened == o.opened && s.expiresAt.Equal(o.expiresAt) &&
		s.retrievalSession == o.retrievalSession
}

func (s v4Secret) String() string {
	return fmt.Sprintf("{%s key=%s size=%d created=%v tokens=%t opened=%t expires=%v session=%t}",
		s.state, s.storageKey, s.blobSize, deref(s.createdAt), s.hasTokens, s.opened, s.expiresAt, s.retrievalSession)
}

// TestMigration_004KeepsOnlySecretsThatCanStillBeRead runs migration 004 up,
// down and up again over a secret in every state it can be in, and the
// uploads, objects and retrieval sessions that go with them.
func TestMigration_004KeepsOnlySecretsThatCanStillBeRead(t *testing.T) {
	conn, migrator := migrationDatabase(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := conn.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	queryStrings := func(sql string, args ...any) []string {
		t.Helper()
		rows, err := conn.Query(ctx, sql, args...)
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		values, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return values
	}
	checkConstraints := func() []string {
		t.Helper()
		return queryStrings("SELECT conname FROM pg_constraint WHERE conrelid = 'secrets'::regclass AND contype = 'c' ORDER BY conname")
	}
	columns := func(table string) []string {
		t.Helper()
		return queryStrings("SELECT column_name || ' ' || is_nullable FROM information_schema.columns WHERE table_name = $1 ORDER BY column_name", table)
	}
	secretIndexes := func() []string {
		t.Helper()
		return queryStrings("SELECT indexname FROM pg_indexes WHERE tablename = 'secrets' AND indexname LIKE 'idx_%' ORDER BY indexname")
	}

	if err := migrator.MigrateTo(ctx, 3); err != nil {
		t.Fatalf("migrate to 3: %v", err)
	}
	// The names Postgres gave the checks are the ones production has, which
	// 004 drops by name.
	v3Checks := []string{"secrets_check", "secrets_check1", "secrets_check2", "secrets_check3", "secrets_check4",
		"secrets_check5", "secrets_outcome_check", "secrets_state_check"}
	if got := checkConstraints(); !slices.Equal(got, v3Checks) {
		t.Fatalf("checks at version 3 = %v, want %v", got, v3Checks)
	}
	v3Columns, v3Indexes := columns("secrets"), secretIndexes()

	// An upload started at startedAt with an hour to live; a secret created
	// at createdAt, both to the microsecond.
	startedAt := time.Date(2026, 10, 9, 12, 0, 7, 123456000, time.UTC)
	createdAt := time.Date(2026, 10, 9, 12, 3, 41, 654321000, time.UTC)
	expiresAt := startedAt.Add(time.Hour)
	opened, deleted := ptr("opened"), ptr("deleted")
	secrets := []v3Secret{
		{id: "uploading", state: "uploading", storageKey: ptr("blobs/uploading"), blobSize: 1},
		{id: "live", state: "live", storageKey: ptr("blobs/live"), blobSize: 2, createdAt: &createdAt},
		{id: "live-opened", state: "live", storageKey: ptr("blobs/live-opened"), blobSize: 3, createdAt: &createdAt, opened: true},
		{id: "draining", state: "ended", storageKey: ptr("blobs/draining"), blobSize: 4, burnAfterRead: true, createdAt: &createdAt, outcome: opened},
		{id: "drained", state: "ended", blobSize: 5, burnAfterRead: true, createdAt: &createdAt, outcome: opened},
		{id: "deleted", state: "ended", blobSize: 6, burnAfterRead: true, createdAt: &createdAt, outcome: deleted},
		{id: "opened-deleted", state: "ended", blobSize: 7, createdAt: &createdAt, opened: true, outcome: deleted},
	}
	for _, s := range secrets {
		key := "blobs/" + s.id
		exec("INSERT INTO objects (storage_key, state, created_at, doomed) VALUES ($1, $2, $3, $4)",
			key, map[bool]string{true: "writing", false: "stored"}[s.state == "uploading"], startedAt, s.storageKey == nil)
		var meta, blobHash, deletionHash *string
		if s.state != "ended" {
			meta, blobHash, deletionHash = ptr("v2$meta"), ptr("b"), ptr("d")
		}
		exec(`INSERT INTO secrets (public_id, state, storage_key, metadata_token_hash, blob_token_hash, deletion_token_hash,
				encrypted_meta, blob_size, burn_after_read, expires_at, created_at, opened, outcome)
			VALUES ($1, $2, $3, 'm', $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			s.id, s.state, s.storageKey, blobHash, deletionHash, meta, s.blobSize, s.burnAfterRead, expiresAt, s.createdAt, s.opened, s.outcome)
	}
	// The draining secret's download still runs; the drained one's ended.
	exec("INSERT INTO retrieval_sessions (session_token_hash, public_id, expires_at) VALUES ('running', 'draining', $1), ('ended', 'drained', $2)",
		time.Now().Add(time.Hour), startedAt)
	finishedAt := createdAt
	exec("INSERT INTO uploads (session_id, public_id, upload_token_hash, state, expires_at) VALUES ('up-uploading', 'uploading', 'u', 'uploading', $1)",
		startedAt.Add(24*time.Hour))
	exec("INSERT INTO uploads (session_id, public_id, upload_token_hash, state, expires_at, finished_at) VALUES ('up-live', 'live', 'u', 'completed', $1, $2)",
		startedAt.Add(24*time.Hour), finishedAt)
	exec("INSERT INTO uploads (session_id, public_id, upload_token_hash, state, expires_at, finished_at) VALUES ('up-deleted', 'deleted', 'u', 'completed', $1, $2)",
		startedAt.Add(24*time.Hour), finishedAt)
	exec("INSERT INTO uploads (session_id, upload_token_hash, state, expires_at, finished_at) VALUES ('up-abandoned', 'u', 'abandoned', $1, $2)",
		startedAt.Add(24*time.Hour), finishedAt)

	minute := createdAt.Truncate(time.Minute)
	assertV4 := func(after string) {
		t.Helper()
		var ids []string
		for _, s := range secrets {
			var want v4Secret
			switch {
			case s.state == "uploading":
				want = v4Secret{state: "uploading", hasTokens: true}
			case s.state == "live":
				// Live secrets keep their expiry, and their creation to the minute.
				want = v4Secret{state: "live", hasTokens: true, createdAt: &minute, opened: s.opened}
			case s.storageKey != nil:
				// An opened one-time secret still downloading keeps only what
				// the download needs.
				want = v4Secret{state: "closing", retrievalSession: true}
			default:
				// Deleted secrets, and opened ones whose download ended, are gone.
				continue
			}
			ids = append(ids, s.id)
			want.storageKey, want.blobSize, want.expiresAt = *s.storageKey, s.blobSize, expiresAt
			var got v4Secret
			if err := conn.QueryRow(ctx, `
				SELECT state, storage_key, blob_size, created_at,
					num_nonnulls(metadata_token_hash, blob_token_hash, deletion_token_hash, encrypted_meta) = 4,
					opened, expires_at,
					EXISTS (SELECT 1 FROM retrieval_sessions AS rs WHERE rs.public_id = s.public_id)
				FROM secrets AS s
				WHERE public_id = $1`, s.id).
				Scan(&got.state, &got.storageKey, &got.blobSize, &got.createdAt, &got.hasTokens, &got.opened, &got.expiresAt, &got.retrievalSession); err != nil {
				t.Fatalf("after %s: read %s: %v", after, s.id, err)
			}
			if !got.equal(want) {
				t.Errorf("after %s: %s = %s, want %s", after, s.id, got, want)
			}
		}
		if got := queryStrings("SELECT public_id FROM secrets ORDER BY public_id"); !slices.Equal(got, slices.Sorted(slices.Values(ids))) {
			t.Errorf("after %s: secrets %v, want only %v", after, got, ids)
		}
		// The gone secrets' sessions went with them, and their uploads forgot them.
		if got := queryStrings("SELECT session_token_hash FROM retrieval_sessions"); !slices.Equal(got, []string{"running"}) {
			t.Errorf("after %s: retrieval sessions %v, want only the running download's", after, got)
		}
		wantChecks := []string{"secrets_closing_keeps_only_the_download", "secrets_closing_only_one_time",
			"secrets_created_while_live", "secrets_known_state", "secrets_opened_only_live_reusable"}
		if got := checkConstraints(); !slices.Equal(got, wantChecks) {
			t.Errorf("after %s: checks = %v, want %v", after, got, wantChecks)
		}
		wantColumns := []string{"blob_size NO", "blob_token_hash YES", "burn_after_read NO", "created_at YES",
			"deletion_token_hash YES", "encrypted_meta YES", "expires_at NO", "metadata_token_hash YES", "opened NO",
			"public_id NO", "state NO", "storage_key NO"}
		if got := columns("secrets"); !slices.Equal(got, wantColumns) {
			t.Errorf("after %s: secrets columns = %v, want %v", after, got, wantColumns)
		}
		if slices.Contains(columns("objects"), "created_at NO") || !slices.Contains(columns("uploads"), "lifetime YES") {
			t.Errorf("after %s: objects.created_at is still there or uploads.lifetime is missing", after)
		}
		if got := secretIndexes(); !slices.Equal(got, []string{"idx_secrets_closing", "idx_secrets_expires_at"}) {
			t.Errorf("after %s: indexes on secrets = %v", after, got)
		}
		var index string
		if err := conn.QueryRow(ctx, "SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_objects_doomed'").Scan(&index); err != nil {
			t.Fatalf("read index: %v", err)
		}
		if !strings.Contains(index, "(failed_removals, storage_key) WHERE doomed") {
			t.Errorf("after %s: idx_objects_doomed = %s", after, index)
		}
	}

	if err := migrator.MigrateTo(ctx, 4); err != nil {
		t.Fatalf("migrate to 4: %v", err)
	}
	assertV4("migrating up")
	// The upload under way waits with its lifetime; the finished ones have
	// none, and the deleted secret's forgot it. All their times are to the
	// minute.
	var uploading, finished, forgot int
	if err := conn.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE session_id = 'up-uploading' AND lifetime = interval '1 hour' AND finished_at IS NULL),
			count(*) FILTER (WHERE session_id <> 'up-uploading' AND lifetime IS NULL AND finished_at = $1),
			count(*) FILTER (WHERE session_id = 'up-deleted' AND public_id IS NULL)
		FROM uploads
		WHERE expires_at = $2`, minute, startedAt.Add(24*time.Hour).Truncate(time.Minute)).Scan(&uploading, &finished, &forgot); err != nil {
		t.Fatalf("read uploads: %v", err)
	}
	if uploading != 1 || finished != 3 || forgot != 1 {
		t.Errorf("uploads: %d under way, %d finished, %d forgot their secret; want 1, 3 and 1", uploading, finished, forgot)
	}

	// Down again: a valid version 3, with the closing secret as an opened
	// one. The deleted ones stay gone.
	if err := migrator.MigrateTo(ctx, 3); err != nil {
		t.Fatalf("migrate down to 3: %v", err)
	}
	if got := checkConstraints(); !slices.Equal(got, v3Checks) {
		t.Errorf("checks after rolling back = %v, want %v", got, v3Checks)
	}
	if got := columns("secrets"); !slices.Equal(got, v3Columns) {
		t.Errorf("secrets columns after rolling back = %v, want %v", got, v3Columns)
	}
	if got := secretIndexes(); !slices.Equal(got, v3Indexes) {
		t.Errorf("indexes on secrets after rolling back = %v, want %v", got, v3Indexes)
	}
	for _, s := range secrets {
		var state string
		var outcome *string
		var opened, hasCreatedAt bool
		err := conn.QueryRow(ctx, "SELECT state, outcome, opened, created_at IS NOT NULL FROM secrets WHERE public_id = $1", s.id).
			Scan(&state, &outcome, &opened, &hasCreatedAt)
		if s.state == "ended" && s.storageKey == nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Errorf("after rolling back: %s is back (%v)", s.id, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("read %s: %v", s.id, err)
		}
		if state != s.state || !equalPtr(outcome, s.outcome) || opened != (s.opened && s.state == "live") || hasCreatedAt != (s.state != "uploading") {
			t.Errorf("after rolling back: %s is %s with outcome %v, opened %t, created_at %t; want %s, %v, %t, %t",
				s.id, state, deref(outcome), opened, hasCreatedAt, s.state, deref(s.outcome), s.opened && s.state == "live", s.state != "uploading")
		}
	}
	if slices.Contains(columns("uploads"), "lifetime YES") || !slices.Contains(columns("objects"), "created_at NO") {
		t.Error("after rolling back: uploads.lifetime is still there or objects.created_at is missing")
	}

	if err := migrator.Migrate(ctx); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
	assertV4("migrating up again")
}

func equalPtr[T comparable](a, b *T) bool {
	return (a == nil) == (b == nil) && (a == nil || *a == *b)
}

func deref[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}
