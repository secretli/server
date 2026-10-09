package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgadapter "github.com/secretli/server/internal/adapter/postgres"
	"github.com/secretli/server/internal/domain"
	tokencrypto "github.com/secretli/server/internal/platform/crypto"
)

// testBatchSize is larger than any test's backlog unless a test is about batching.
const testBatchSize = 100

// Postgres keeps microseconds, so moments that are compared are rounded first.
func moment(t time.Time) time.Time {
	return t.Truncate(time.Microsecond)
}

func newTestSecret(publicID string, expiresAt time.Time) *domain.Secret {
	return &domain.Secret{
		PublicID:          publicID,
		MetadataTokenHash: tokencrypto.TokenHash("metadata-token-" + publicID),
		BlobTokenHash:     tokencrypto.TokenHash("blob-token-" + publicID),
		DeletionTokenHash: tokencrypto.TokenHash("deletion-token-" + publicID),
		EncryptedMeta:     "v2$nonce$meta-" + publicID,
		BlobSize:          1024,
		BurnAfterRead:     false,
		ExpiresAt:         expiresAt,
	}
}

// testLifetime is the lifetime of the secrets the tests upload.
const testLifetime = time.Hour

// newTestUpload returns the upload under sessionID that creates secret, and
// points the secret at the session's own object, as the service does.
func newTestUpload(sessionID string, secret *domain.Secret, expiresAt time.Time) *domain.Upload {
	secret.StorageKey = domain.UploadStorageKey(sessionID)
	return &domain.Upload{
		SessionID:       sessionID,
		UploadTokenHash: tokencrypto.TokenHash("upload-token-" + sessionID),
		ExpiresAt:       expiresAt,
		Lifetime:        testLifetime,
	}
}

// uploadSessionOf is the session mustCreate uploads a secret under.
func uploadSessionOf(publicID string) string {
	return "upload-" + publicID
}

func mustStartUpload(t *testing.T, repo *pgadapter.SecretRepo, sessionID string, secret *domain.Secret, uploadExpiresAt time.Time) {
	t.Helper()
	if err := repo.StartUpload(context.Background(), secret, newTestUpload(sessionID, secret, uploadExpiresAt)); err != nil {
		t.Fatalf("start upload %s for %s: %v", sessionID, secret.PublicID, err)
	}
}

func mustComplete(t *testing.T, repo *pgadapter.SecretRepo, sessionID string, now time.Time) {
	t.Helper()
	if _, err := repo.CompleteUpload(context.Background(), sessionID, now, noopFinalize); err != nil {
		t.Fatalf("complete upload %s: %v", sessionID, err)
	}
}

// mustCreate uploads a live secret that expires at secret.ExpiresAt.
// Completing gives a secret its expiry from its lifetime, which the upload
// tests check; here the expiry is then moved to where the test wants it,
// into the past too.
func mustCreate(t *testing.T, repo *pgadapter.SecretRepo, secret *domain.Secret) {
	t.Helper()
	now := time.Now()
	sessionID := uploadSessionOf(secret.PublicID)
	mustStartUpload(t, repo, sessionID, secret, now.Add(time.Hour))
	mustComplete(t, repo, sessionID, now)
	setExpiry(t, secret.PublicID, secret.ExpiresAt)
}

// setExpiry moves a secret's expiry, and its id's with it, as completing the
// upload would have set it.
func setExpiry(t *testing.T, publicID string, expiresAt time.Time) {
	t.Helper()
	for _, table := range []string{"secrets", "public_ids"} {
		if _, err := testDBPool.Exec(context.Background(),
			"UPDATE "+table+" SET expires_at = $2 WHERE public_id = $1", publicID, expiresAt); err != nil {
			t.Fatalf("set expiry of %s in %s: %v", publicID, table, err)
		}
	}
}

// openAs starts a retrieval session on a secret made by newTestSecret, as a
// recipient, or as the owner when asOwner is set.
func openAs(repo *pgadapter.SecretRepo, publicID, session string, asOwner bool, now time.Time) (*domain.Secret, error) {
	deletionHash := ""
	if asOwner {
		deletionHash = tokencrypto.TokenHash("deletion-token-" + publicID)
	}
	return repo.StartRetrievalSession(
		context.Background(),
		publicID,
		tokencrypto.TokenHash("blob-token-"+publicID),
		deletionHash,
		tokencrypto.TokenHash(session),
		now.Add(15*time.Minute),
		now,
	)
}

func mustOpen(t *testing.T, repo *pgadapter.SecretRepo, publicID, session string, asOwner bool, now time.Time) *domain.Secret {
	t.Helper()
	secret, err := openAs(repo, publicID, session, asOwner, now)
	if err != nil {
		t.Fatalf("open %s: %v", publicID, err)
	}
	return secret
}

func download(repo *pgadapter.SecretRepo, publicID, session string, now time.Time) (*domain.Secret, error) {
	return repo.GetByRetrievalSession(context.Background(), publicID, tokencrypto.TokenHash(session), now)
}

func mustGetSecret(t *testing.T, repo *pgadapter.SecretRepo, publicID string) *domain.Secret {
	t.Helper()
	secret, err := repo.GetSecret(context.Background(), publicID)
	if err != nil {
		t.Fatalf("get secret %s: %v", publicID, err)
	}
	return secret
}

func assertSecretGone(t *testing.T, repo *pgadapter.SecretRepo, publicID string) {
	t.Helper()
	if _, err := repo.GetSecret(context.Background(), publicID); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("secret %s: err = %v, want it gone", publicID, err)
	}
}

// assertClosing checks that an opened one-time secret is closing and keeps
// nothing but what the download that opened it needs: its object, the
// object's size and the expiry. No content, no token hash, no creation time.
func assertClosing(t *testing.T, repo *pgadapter.SecretRepo, original *domain.Secret) {
	t.Helper()
	got := mustGetSecret(t, repo, original.PublicID)
	want := domain.Secret{
		PublicID:      original.PublicID,
		State:         domain.SecretClosing,
		StorageKey:    original.StorageKey,
		BlobSize:      original.BlobSize,
		BurnAfterRead: true,
		ExpiresAt:     got.ExpiresAt,
	}
	if *got != want {
		t.Errorf("closing secret = %+v, want only %+v", *got, want)
	}
}

// secretRow is what a secret's row holds of its times, read past the
// repository.
type secretRow struct {
	CreatedAt *time.Time
	ExpiresAt time.Time
}

func mustGetSecretRow(t *testing.T, pool *pgxpool.Pool, publicID string) secretRow {
	t.Helper()
	var r secretRow
	if err := pool.QueryRow(context.Background(),
		"SELECT created_at, expires_at FROM secrets WHERE public_id = $1", publicID,
	).Scan(&r.CreatedAt, &r.ExpiresAt); err != nil {
		t.Fatalf("query secret %s: %v", publicID, err)
	}
	return r
}

// objectRow is an object's row as the ledger holds it.
type objectRow struct {
	State          string
	S3UploadID     *string
	Doomed         bool
	FailedRemovals int
}

// getObject reads an object's row, or nil if the ledger does not know it.
func getObject(t *testing.T, pool *pgxpool.Pool, storageKey string) *objectRow {
	t.Helper()
	var o objectRow
	err := pool.QueryRow(context.Background(),
		"SELECT state, s3_upload_id, doomed, failed_removals FROM objects WHERE storage_key = $1", storageKey,
	).Scan(&o.State, &o.S3UploadID, &o.Doomed, &o.FailedRemovals)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		t.Fatalf("query object %s: %v", storageKey, err)
	}
	return &o
}

func mustGetObject(t *testing.T, pool *pgxpool.Pool, storageKey string) *objectRow {
	t.Helper()
	o := getObject(t, pool, storageKey)
	if o == nil {
		t.Fatalf("object %s is not in the ledger", storageKey)
	}
	return o
}

func assertDoomed(t *testing.T, pool *pgxpool.Pool, storageKey string) {
	t.Helper()
	if o := mustGetObject(t, pool, storageKey); !o.Doomed {
		t.Errorf("object %s is not doomed", storageKey)
	}
}

func assertNotDoomed(t *testing.T, pool *pgxpool.Pool, storageKey string) {
	t.Helper()
	if o := mustGetObject(t, pool, storageKey); o.Doomed {
		t.Errorf("object %s is doomed, want it kept", storageKey)
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func TestSecretRepo_StorageStatsCountTotalsOnly(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())

	live := newTestSecret("live", now.Add(time.Hour))
	live.BlobSize = 100
	mustCreate(t, repo, live)
	uploading := newTestSecret("uploading", now.Add(time.Hour))
	uploading.BlobSize = 50
	mustStartUpload(t, repo, "up-uploading", uploading, now.Add(time.Hour))
	deleted := newTestSecret("deleted", now.Add(time.Hour))
	deleted.BlobSize = 1000
	mustCreate(t, repo, deleted)
	if err := repo.Delete(ctx, "deleted", now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Opened one-time secrets: one still drains, the other let go of its
	// object once its download ended.
	for _, s := range []struct {
		id       string
		size     int64
		openedAt time.Time
	}{{"draining", 7, now}, {"drained", 3000, now.Add(-time.Hour)}} {
		secret := newTestSecret(s.id, now.Add(time.Hour))
		secret.BlobSize, secret.BurnAfterRead = s.size, true
		mustCreate(t, repo, secret)
		mustOpen(t, repo, s.id, "opener-"+s.id, false, s.openedAt)
	}
	if n, err := repo.DeleteDrainedSecrets(ctx, now, testBatchSize); err != nil || n != 1 {
		t.Fatalf("release drained secrets = %d, %v; want 1", n, err)
	}

	// One secret can be opened; storage holds it, the upload under way and
	// the download that drains; the deleted and drained secrets' objects wait
	// for the cleanup and no longer count.
	stats, err := repo.StorageStats(ctx, now)
	if err != nil {
		t.Fatalf("storage stats: %v", err)
	}
	if want := (domain.StorageStats{LiveSecrets: 1, StoredBytes: 157, DoomedObjects: 2}); stats != want {
		t.Errorf("stats = %+v, want %+v", stats, want)
	}
}

func TestSecretRepo_GetSecretReturnsASecretInAnyState(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	expiresAt := moment(now.Add(time.Hour))

	secret := newTestSecret("get-any", expiresAt)
	secret.BurnAfterRead = true
	mustStartUpload(t, repo, "upload-get-any", secret, now.Add(time.Hour))

	// A secret is filed when its upload starts, already with all its fields.
	got := mustGetSecret(t, repo, "get-any")
	want := domain.Secret{
		PublicID:          "get-any",
		State:             domain.SecretUploading,
		StorageKey:        domain.UploadStorageKey("upload-get-any"),
		MetadataTokenHash: tokencrypto.TokenHash("metadata-token-get-any"),
		BlobTokenHash:     tokencrypto.TokenHash("blob-token-get-any"),
		DeletionTokenHash: tokencrypto.TokenHash("deletion-token-get-any"),
		EncryptedMeta:     "v2$nonce$meta-get-any",
		BlobSize:          1024,
		BurnAfterRead:     true,
	}
	gotFields := *got
	gotFields.ExpiresAt, gotFields.CreatedAt = time.Time{}, nil
	if gotFields != want {
		t.Errorf("uploading secret = %+v, want %+v", gotFields, want)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("expires_at = %v, want %v", got.ExpiresAt, expiresAt)
	}
	if got.CreatedAt != nil {
		t.Errorf("created_at = %v, want none while uploading", *got.CreatedAt)
	}
	if got.Readable(now) {
		t.Error("an uploading secret is readable")
	}

	// Expired secrets are returned until the cleanup deletes them.
	mustCreate(t, repo, newTestSecret("get-expired", now.Add(-time.Minute)))
	if got := mustGetSecret(t, repo, "get-expired"); got.State != domain.SecretLive || got.Readable(now) {
		t.Errorf("expired secret: state = %q, readable = %v; want live and not readable", got.State, got.Readable(now))
	}

	if _, err := repo.GetSecret(ctx, "unknown"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown secret: err = %v, want ErrNotFound", err)
	}
}

func TestSecretRepo_OpeningAOneTimeSecretClosesIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		asOwner bool
	}{
		{name: "by a recipient"},
		// There is no owner's preview of a one-time secret: opening it closes
		// it.
		{name: "by the owner", asOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := setupTestDB(t)
			repo := pgadapter.NewSecretRepo(pool)
			now := moment(time.Now())
			secret := newTestSecret("one-time", now.Add(time.Hour))
			secret.BurnAfterRead = true
			mustCreate(t, repo, secret)

			opened := mustOpen(t, repo, "one-time", "opener", tc.asOwner, now)

			// The answer still carries what the opener needs to read it.
			if opened.State != domain.SecretClosing {
				t.Errorf("returned state = %q, want closing", opened.State)
			}
			if opened.EncryptedMeta != "v2$nonce$meta-one-time" || opened.StorageKey != secret.StorageKey || opened.BlobSize != secret.BlobSize {
				t.Errorf("returned meta = %q, storage key = %q, blob size %d; want the secret's", opened.EncryptedMeta, opened.StorageKey, opened.BlobSize)
			}

			// Whoever opened it, it keeps only what the download needs.
			assertClosing(t, repo, secret)
			if mustGetSecret(t, repo, "one-time").Readable(now) {
				t.Error("a closing secret is readable")
			}
			assertNotDoomed(t, pool, secret.StorageKey)

			got, err := download(repo, "one-time", "opener", now)
			if err != nil {
				t.Errorf("opener's download: %v, want it allowed until the session ends", err)
			} else if got.BlobSize != secret.BlobSize {
				t.Errorf("download blob size = %d, want %d for the range reads", got.BlobSize, secret.BlobSize)
			}
			if _, err := openAs(repo, "one-time", "second", false, now); !errors.Is(err, domain.ErrNotFound) {
				t.Errorf("second open: err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestSecretRepo_RecipientOpeningAReusableSecretMarksItOpened(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustCreate(t, repo, newTestSecret("reusable", now.Add(time.Hour)))

	// The owner looking at their own secret is not a recipient getting it.
	if got := mustOpen(t, repo, "reusable", "owner", true, now); got.Opened {
		t.Error("owner's open returned opened = true")
	}
	if mustGetSecret(t, repo, "reusable").Opened {
		t.Error("owner's open marked the secret opened")
	}

	// A wrong deletion token is just a recipient.
	got, err := repo.StartRetrievalSession(ctx, "reusable",
		tokencrypto.TokenHash("blob-token-reusable"), tokencrypto.TokenHash("not-the-deletion-token"),
		tokencrypto.TokenHash("recipient"), now.Add(15*time.Minute), now)
	if err != nil {
		t.Fatalf("recipient's open: %v", err)
	}
	if !got.Opened {
		t.Error("recipient's open returned opened = false")
	}
	stored := mustGetSecret(t, repo, "reusable")
	if !stored.Opened || stored.State != domain.SecretLive || stored.EncryptedMeta == "" {
		t.Errorf("after recipient: opened = %v, state = %q, meta = %q; want opened, still live with its content",
			stored.Opened, stored.State, stored.EncryptedMeta)
	}

	// It stays readable for everyone, and opened stays set.
	mustOpen(t, repo, "reusable", "recipient-again", false, now)
	mustOpen(t, repo, "reusable", "owner-again", true, now)
	if !mustGetSecret(t, repo, "reusable").Opened {
		t.Error("opened flag was cleared by a later open")
	}
	for _, session := range []string{"owner", "recipient", "recipient-again", "owner-again"} {
		if _, err := download(repo, "reusable", session, now); err != nil {
			t.Errorf("download with %s's session: %v", session, err)
		}
	}
}

func TestSecretRepo_StartRetrievalSessionRefusesAWrongBlobToken(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	secret := newTestSecret("wrong-blob", now.Add(time.Hour))
	secret.BurnAfterRead = true
	mustCreate(t, repo, secret)

	_, err := repo.StartRetrievalSession(context.Background(), "wrong-blob",
		tokencrypto.TokenHash("not-the-blob-token"), "", tokencrypto.TokenHash("session"), now.Add(15*time.Minute), now)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}

	// A wrong guess neither burns the secret nor opens a session.
	if got := mustGetSecret(t, repo, "wrong-blob"); got.State != domain.SecretLive {
		t.Errorf("state = %q, want live", got.State)
	}
	if n := countRows(t, pool, "SELECT count(*) FROM retrieval_sessions"); n != 0 {
		t.Errorf("retrieval sessions = %d, want 0", n)
	}
}

func TestSecretRepo_StartRetrievalSessionNeedsAReadableSecret(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())

	uploading := newTestSecret("not-yet", now.Add(time.Hour))
	mustStartUpload(t, repo, "upload-not-yet", uploading, now.Add(time.Hour))
	mustCreate(t, repo, newTestSecret("expired", now.Add(-time.Second)))
	mustCreate(t, repo, newTestSecret("deleted", now.Add(time.Hour)))
	if err := repo.Delete(context.Background(), "deleted", now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	burned := newTestSecret("burned", now.Add(time.Hour))
	burned.BurnAfterRead = true
	mustCreate(t, repo, burned)
	mustOpen(t, repo, "burned", "first", false, now)

	for _, id := range []string{"unknown", "not-yet", "expired", "deleted", "burned"} {
		if _, err := openAs(repo, id, "session-"+id, false, now); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", id, err)
		}
	}
	// The expiry is exclusive: a secret is gone at the moment it expires.
	mustCreate(t, repo, newTestSecret("at-expiry", now))
	if _, err := openAs(repo, "at-expiry", "session-at-expiry", false, now); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("at expiry: err = %v, want ErrNotFound", err)
	}
}

func TestSecretRepo_ConcurrentOpensOfAOneTimeSecretSucceedOnce(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	secret := newTestSecret("race", now.Add(time.Hour))
	secret.BurnAfterRead = true
	mustCreate(t, repo, secret)

	const callers = 8
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			// Each opener brings its own session token, so losing can only
			// mean the secret is gone.
			_, errs[i] = openAs(repo, "race", fmt.Sprintf("racer-%d", i), false, now)
		})
	}
	wg.Wait()

	winners := 0
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case !errors.Is(err, domain.ErrNotFound):
			t.Errorf("caller %d: err = %v, want nil or ErrNotFound", i, err)
		}
	}
	if winners != 1 {
		t.Errorf("%d callers opened the one-time secret, want exactly 1", winners)
	}
	if n := countRows(t, pool, "SELECT count(*) FROM retrieval_sessions WHERE public_id = 'race'"); n != 1 {
		t.Errorf("retrieval sessions = %d, want 1", n)
	}
}

func TestSecretRepo_GetByRetrievalSession(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustCreate(t, repo, newTestSecret("dl", now.Add(time.Hour)))
	mustCreate(t, repo, newTestSecret("dl-other", now.Add(time.Hour)))
	mustOpen(t, repo, "dl", "session", false, now)

	got, err := download(repo, "dl", "session", now)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got.PublicID != "dl" || got.StorageKey != domain.UploadStorageKey(uploadSessionOf("dl")) || got.BlobSize != 1024 {
		t.Errorf("download = %+v, want the secret with its object", got)
	}

	for _, tc := range []struct {
		name, publicID, session string
		at                      time.Time
	}{
		{"wrong session", "dl", "other-session", now},
		{"another secret's id", "dl-other", "session", now},
		// openAs gives sessions 15 minutes.
		{"session ended", "dl", "session", now.Add(15 * time.Minute)},
	} {
		if _, err := download(repo, tc.publicID, tc.session, tc.at); !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("%s: err = %v, want ErrForbidden", tc.name, err)
		}
	}

	// A session longer than the secret ends with the secret.
	mustCreate(t, repo, newTestSecret("dl-short", now.Add(time.Minute)))
	if _, err := repo.StartRetrievalSession(ctx, "dl-short", tokencrypto.TokenHash("blob-token-dl-short"), "",
		tokencrypto.TokenHash("long-session"), now.Add(time.Hour), now); err != nil {
		t.Fatalf("open dl-short: %v", err)
	}
	if _, err := download(repo, "dl-short", "long-session", now.Add(time.Minute)); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("expired secret: err = %v, want ErrForbidden", err)
	}
}

func TestSecretRepo_DeleteRemovesTheSecretAndDoomsItsObject(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	secret := newTestSecret("doomed", now.Add(time.Hour))
	mustCreate(t, repo, secret)
	mustOpen(t, repo, "doomed", "recipient", false, now)

	deletedAt := moment(now.Add(time.Second))
	if err := repo.Delete(ctx, "doomed", deletedAt); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Nothing of it is kept, its sessions included; its object is doomed.
	assertSecretGone(t, repo, "doomed")
	if n := countRows(t, pool, "SELECT count(*) FROM retrieval_sessions WHERE public_id = 'doomed'"); n != 0 {
		t.Errorf("the deleted secret left %d retrieval sessions", n)
	}
	assertDoomed(t, pool, secret.StorageKey)

	// A running download ends at once, and the secret is gone for everyone.
	if _, err := download(repo, "doomed", "recipient", deletedAt); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("running download: err = %v, want ErrForbidden", err)
	}
	if _, err := openAs(repo, "doomed", "late", false, deletedAt); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("open after delete: err = %v, want ErrNotFound", err)
	}
	if err := repo.Delete(ctx, "doomed", deletedAt); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("second delete: err = %v, want ErrNotFound", err)
	}
}

func TestSecretRepo_DeleteNeedsAReadableSecret(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())

	uploading := newTestSecret("not-yet", now.Add(time.Hour))
	mustStartUpload(t, repo, "upload-not-yet", uploading, now.Add(time.Hour))
	expired := newTestSecret("expired", now.Add(-time.Second))
	mustCreate(t, repo, expired)
	burned := newTestSecret("burned", now.Add(time.Hour))
	burned.BurnAfterRead = true
	mustCreate(t, repo, burned)
	mustOpen(t, repo, "burned", "opener", false, now)

	for _, id := range []string{"unknown", "not-yet", "expired", "burned"} {
		if err := repo.Delete(ctx, id, now); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", id, err)
		}
	}

	// Nothing was touched: the upload goes on, the opened secret still drains.
	if got := mustGetSecret(t, repo, "not-yet"); got.State != domain.SecretUploading {
		t.Errorf("uploading secret state = %q, want uploading", got.State)
	}
	assertClosing(t, repo, burned)
	for _, key := range []string{uploading.StorageKey, expired.StorageKey, burned.StorageKey} {
		assertNotDoomed(t, pool, key)
	}
	if _, err := download(repo, "burned", "opener", now); err != nil {
		t.Errorf("opener's download after a refused delete: %v", err)
	}
}
