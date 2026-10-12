package postgres_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	pgadapter "github.com/secretli/server/internal/adapter/postgres"
)

// testCA is a certificate authority for one test, as CloudNativePG keeps one
// per cluster.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue makes a server certificate for these names, and its key, in PEM.
func (ca *testCA) issue(t *testing.T, names ...string) (certPEM, keyPEM []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), cert
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

// accepts reports whether a connection's TLS settings accept cert for host.
func accepts(t *testing.T, config *pgxpool.Config, cert *x509.Certificate, host string) bool {
	t.Helper()
	conn := config.ConnConfig.Copy()
	if err := config.BeforeConnect(context.Background(), conn); err != nil {
		t.Fatalf("BeforeConnect: %v", err)
	}
	_, err := cert.Verify(x509.VerifyOptions{Roots: conn.TLSConfig.RootCAs, DNSName: host})
	return err == nil
}

// Each new connection verifies against the CA file as it is then, so a CA
// renewed while the server runs is taken without a restart.
func TestPoolRereadsTheCAForEveryConnection(t *testing.T) {
	first, second := newTestCA(t, "first CA"), newTestCA(t, "second CA")
	_, _, firstCert := first.issue(t, "secretli-db-rw")
	_, _, secondCert := second.issue(t, "secretli-db-rw")
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, caFile, first.pem)

	config, err := pgadapter.PoolConfig("postgres://secretli@secretli-db-rw:5432/secretli?sslmode=verify-full&sslrootcert=" + caFile)
	if err != nil {
		t.Fatal(err)
	}
	if config.BeforeConnect == nil {
		t.Fatal("no hook rereads the CA")
	}
	if !accepts(t, config, firstCert, "secretli-db-rw") || accepts(t, config, secondCert, "secretli-db-rw") {
		t.Error("before the renewal, only the first CA's certificate should pass")
	}
	if accepts(t, config, firstCert, "someone-else") {
		t.Error("a certificate for another name passed")
	}

	writeFile(t, caFile, second.pem)
	if accepts(t, config, firstCert, "secretli-db-rw") || !accepts(t, config, secondCert, "secretli-db-rw") {
		t.Error("after the renewal, only the second CA's certificate should pass")
	}

	if err := os.Remove(caFile); err != nil {
		t.Fatal(err)
	}
	if err := config.BeforeConnect(context.Background(), config.ConnConfig.Copy()); err == nil || !strings.Contains(err.Error(), "read the database's CA") {
		t.Errorf("a missing CA file: err = %v, want it refused", err)
	}
}

// PGSSLROOTCERT and PGSSLMODE count as pgx takes them, as the deployment
// sets them; the URL from CloudNativePG names neither.
func TestPoolRereadsTheCAFromTheEnvironment(t *testing.T) {
	ca := newTestCA(t, "the CA")
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, caFile, ca.pem)
	t.Setenv("PGSSLMODE", "verify-full")
	t.Setenv("PGSSLROOTCERT", caFile)

	config, err := pgadapter.PoolConfig("postgresql://secretli:pw@secretli-db-rw:5432/secretli")
	if err != nil {
		t.Fatal(err)
	}
	if config.BeforeConnect == nil {
		t.Error("no hook rereads the CA set in the environment")
	}
}

// Without verify-full and a CA file there is nothing to reread, and the
// pool is what pgx makes of the URL.
func TestPoolLeavesOtherModesAlone(t *testing.T) {
	ca := newTestCA(t, "the CA")
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, caFile, ca.pem)
	for _, url := range []string{
		"postgres://u@db:5432/x",
		"postgres://u@db:5432/x?sslmode=disable",
		"postgres://u@db:5432/x?sslmode=prefer",
		"postgres://u@db:5432/x?sslmode=require",
		"postgres://u@db:5432/x?sslmode=verify-full",
		"postgres://u@db:5432/x?sslmode=verify-ca&sslrootcert=" + caFile,
	} {
		config, err := pgadapter.PoolConfig(url)
		if err != nil {
			t.Fatalf("%s: %v", url, err)
		}
		if config.BeforeConnect != nil {
			t.Errorf("%s: a hook was installed", url)
		}
	}
}

// The whole of it against a real Postgres: the server's certificate and the
// CA change while the pool runs, as when CloudNativePG renews its CA, and a
// new connection still verifies. A pool from pgx alone, the control, keeps
// the CA it read at start and refuses.
func TestPoolFollowsARotatedDatabaseCA(t *testing.T) {
	requireDocker(t)
	ctx := context.Background()
	dir := t.TempDir()
	first, second := newTestCA(t, "first CA"), newTestCA(t, "second CA")

	certPEM, keyPEM, _ := first.issue(t, "localhost", "127.0.0.1")
	writeFile(t, filepath.Join(dir, "server.crt"), certPEM)
	writeFile(t, filepath.Join(dir, "server.key"), keyPEM)
	// Postgres reads its key only when the database user owns it.
	install := "mkdir -p /etc/pgtls && install -o postgres -g postgres -m 600 /pgtls-in/server.key /etc/pgtls/server.key && install -o postgres -g postgres -m 644 /pgtls-in/server.crt /etc/pgtls/server.crt"
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:18-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env:          map[string]string{"POSTGRES_USER": "test", "POSTGRES_PASSWORD": "test", "POSTGRES_DB": "secretli_test"},
			Files: []testcontainers.ContainerFile{
				{HostFilePath: filepath.Join(dir, "server.crt"), ContainerFilePath: "/pgtls-in/server.crt", FileMode: 0o644},
				{HostFilePath: filepath.Join(dir, "server.key"), ContainerFilePath: "/pgtls-in/server.key", FileMode: 0o644},
			},
			Entrypoint: []string{"sh", "-c", install + " && exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/etc/pgtls/server.crt -c ssl_key_file=/etc/pgtls/server.key"},
			WaitingFor: wait.ForAll(
				wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
				wait.ForListeningPort("5432/tcp"),
			).WithDeadline(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start postgres with TLS: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatal(err)
	}

	caFile := filepath.Join(dir, "ca.crt")
	writeFile(t, caFile, first.pem)
	url := "postgres://test:test@localhost:" + port.Port() + "/secretli_test?sslmode=verify-full&sslrootcert=" + caFile

	pool, err := pgadapter.NewPool(ctx, url)
	if err != nil {
		t.Fatalf("connect with verify-full against the first CA: %v", err)
	}
	t.Cleanup(pool.Close)
	control, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(control.Close)
	if err := control.Ping(ctx); err != nil {
		t.Fatalf("control: %v", err)
	}

	// The renewal: a certificate from the second CA, which Postgres loads on
	// a reload, and the second CA in the mounted file.
	certPEM, keyPEM, _ = second.issue(t, "localhost", "127.0.0.1")
	if err := container.CopyToContainer(ctx, certPEM, "/pgtls-in/server.crt", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := container.CopyToContainer(ctx, keyPEM, "/pgtls-in/server.key", 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, err := container.Exec(ctx, []string{"sh", "-c", install}); err != nil || code != 0 {
		t.Fatalf("install the second certificate: exit %d, %v", code, err)
	}
	if _, err := pool.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, caFile, second.pem)
	time.Sleep(time.Second) // the reload is a signal; give it a moment

	pool.Reset()
	if err := pool.Ping(ctx); err != nil {
		t.Errorf("a new connection after the renewal: %v", err)
	}
	control.Reset()
	if err := control.Ping(ctx); err == nil {
		t.Error("the control pool connected after the renewal; the test proves nothing")
	}
}
