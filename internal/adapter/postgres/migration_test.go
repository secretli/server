package postgres_test

import (
	"context"
	"os"
	"strings"
	"testing"

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
	if version != 2 {
		t.Errorf("version = %d, want both migrations", version)
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
