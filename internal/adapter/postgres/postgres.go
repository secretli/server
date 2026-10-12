//go:generate sqlc generate -f ../../../sqlc.yaml

package postgres

import (
	"context"
	"crypto/x509"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/tern/v2/migrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// poolConfig is the pool's configuration for databaseURL. When it verifies
// the database's certificate (sslmode=verify-full) against a CA file, given
// as sslrootcert or PGSSLROOTCERT, every new connection reads that file
// again. pgx reads it once otherwise, and CloudNativePG renews its CA
// before the old one expires: Kubernetes updates the mounted file, but a
// pool holding the CA it read at start would stop connecting once that ran
// out.
func poolConfig(databaseURL string) (*pgxpool.Config, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	// Only verify-full verifies through RootCAs, which a connection's own
	// copy of the TLS config can be given; verify-ca keeps the pool it read.
	tlsConfig := config.ConnConfig.TLSConfig
	caFile := rootCertFile(databaseURL)
	if tlsConfig == nil || tlsConfig.InsecureSkipVerify || caFile == "" || caFile == "system" {
		return config, nil
	}
	config.BeforeConnect = func(_ context.Context, conn *pgx.ConnConfig) error {
		roots, err := readCertPool(caFile)
		if err != nil {
			return err
		}
		if conn.TLSConfig != nil {
			conn.TLSConfig.RootCAs = roots
		}
		for _, fallback := range conn.Fallbacks {
			if fallback.TLSConfig != nil {
				fallback.TLSConfig.RootCAs = roots
			}
		}
		return nil
	}
	return config, nil
}

// rootCertFile is the CA file pgx verifies the database's certificate
// against: sslrootcert in the URL, or else PGSSLROOTCERT, as pgx takes it.
func rootCertFile(databaseURL string) string {
	if u, err := url.Parse(databaseURL); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		if file := u.Query().Get("sslrootcert"); file != "" {
			return file
		}
	}
	return os.Getenv("PGSSLROOTCERT")
}

func readCertPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file) //nolint:gosec // the path is the deployment's own setting, as pgx reads it too
	if err != nil {
		return nil, fmt.Errorf("read the database's CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("read the database's CA: no certificate in %s", file)
	}
	return roots, nil
}

// Advisory lock ID for migrations (arbitrary fixed constant).
const migrationLockID = 0x5365637265746C69 // "Secretli" in hex

func NewPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := poolConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return pool, nil
}

func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire connection for migrations: %w", err)
	}
	defer conn.Release()

	slog.Info("acquiring migration lock")
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", migrationLockID); err != nil {
			slog.Error("failed to release migration lock", "error", err)
		}
	}()

	migrator, err := migrate.NewMigrator(ctx, conn.Conn(), "schema_version")
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}

	migrationFiles, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("create migrations sub-FS: %w", err)
	}

	if err := migrator.LoadMigrations(migrationFiles); err != nil {
		return fmt.Errorf("load migrations: %w", err)
	}

	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}

	return nil
}
