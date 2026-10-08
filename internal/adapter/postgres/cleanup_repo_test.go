package postgres_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	pgadapter "github.com/secretli/server/internal/adapter/postgres"
	"github.com/secretli/server/internal/domain"
	tokencrypto "github.com/secretli/server/internal/platform/crypto"
)

// lockRow holds a row lock in another transaction until the test ends, like
// a request or another replica's cleanup would.
func lockRow(t *testing.T, query string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := testDBPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, query, args...); err != nil {
		t.Fatalf("lock row: %v", err)
	}
}

// removeAll is a storage that deletes every object and records the order.
func removeAll(seen *[]string) func(*domain.Object) error {
	return func(object *domain.Object) error {
		*seen = append(*seen, object.StorageKey)
		return nil
	}
}

func TestCleanupRepo_DeleteExpiredRetrievalSessions(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustCreate(t, repo, newTestSecret("sessions", now.Add(time.Hour)))
	mustOpen(t, repo, "sessions", "old", false, now.Add(-time.Hour))
	mustOpen(t, repo, "sessions", "current", false, now)

	n, err := repo.DeleteExpiredRetrievalSessions(ctx, now)
	if err != nil {
		t.Fatalf("delete expired sessions: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d sessions, want 1", n)
	}
	if left := countRows(t, pool, "SELECT count(*) FROM retrieval_sessions"); left != 1 {
		t.Errorf("sessions left = %d, want 1", left)
	}
	if _, err := download(repo, "sessions", "current", now); err != nil {
		t.Errorf("current session: %v", err)
	}
}

func TestCleanupRepo_AbandonExpiredUploads(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())

	mustStartUpload(t, repo, "up-ran-out", newTestSecret("ran-out", now.Add(time.Hour)), now.Add(-time.Minute), now.Add(-time.Hour))
	mustRecordPart(t, repo, newTestUploadPart("up-ran-out", 1, 0, 1024))
	mustStartUpload(t, repo, "up-running", newTestSecret("running", now.Add(time.Hour)), now.Add(time.Minute), now)
	// A completed upload's expiry no longer matters.
	finished := newTestSecret("finished", now.Add(time.Hour))
	mustStartUpload(t, repo, "up-finished", finished, now.Add(-time.Minute), now.Add(-time.Hour))
	mustComplete(t, repo, "up-finished", now.Add(-time.Hour))

	n, err := repo.AbandonExpiredUploads(ctx, now, testBatchSize)
	if err != nil {
		t.Fatalf("abandon expired uploads: %v", err)
	}
	if n != 1 {
		t.Errorf("abandoned %d uploads, want 1", n)
	}

	upload, _ := mustGetUpload(t, repo, "up-ran-out")
	if upload.State != domain.UploadAbandoned || upload.FinishedAt == nil || !upload.FinishedAt.Equal(now) || upload.PublicID != "" {
		t.Errorf("expired upload = %+v, want abandoned at %v without its secret", upload, now)
	}
	assertSecretGone(t, repo, "ran-out")
	assertDoomed(t, pool, "blobs/up-ran-out", now)

	assertUploadState(t, repo, "up-running", domain.UploadUploading)
	assertNotDoomed(t, pool, "blobs/up-running")
	assertUploadState(t, repo, "up-finished", domain.UploadCompleted)
	if got := mustGetSecret(t, repo, "finished"); got.State != domain.SecretLive {
		t.Errorf("finished upload's secret state = %q, want live", got.State)
	}

	// The expired upload's public id is free again.
	mustStartUpload(t, repo, "up-ran-out-again", newTestSecret("ran-out", now.Add(time.Hour)), now.Add(time.Hour), now)

	if n, err := repo.AbandonExpiredUploads(ctx, now, testBatchSize); err != nil || n != 0 {
		t.Errorf("second run = %d, %v; want nothing left", n, err)
	}
}

func TestCleanupRepo_AbandonExpiredUploadsInBatchesOldestFirst(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	for _, tc := range []struct {
		id  string
		ago time.Duration
	}{{"1h", time.Hour}, {"3h", 3 * time.Hour}, {"2h", 2 * time.Hour}} {
		mustStartUpload(t, repo, "up-"+tc.id, newTestSecret(tc.id, now.Add(time.Hour)), now.Add(-tc.ago), now.Add(-4*time.Hour))
	}

	first, err := repo.AbandonExpiredUploads(ctx, now, 2)
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	if first != 2 {
		t.Errorf("first batch = %d, want 2", first)
	}
	assertUploadState(t, repo, "up-3h", domain.UploadAbandoned)
	assertUploadState(t, repo, "up-2h", domain.UploadAbandoned)
	assertUploadState(t, repo, "up-1h", domain.UploadUploading)

	second, err := repo.AbandonExpiredUploads(ctx, now, 2)
	if err != nil {
		t.Fatalf("second batch: %v", err)
	}
	if second != 1 {
		t.Errorf("second batch = %d, want 1", second)
	}
	assertUploadState(t, repo, "up-1h", domain.UploadAbandoned)
}

func TestCleanupRepo_AbandonExpiredUploadsSkipsLockedRows(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	for _, id := range []string{"locked", "free"} {
		mustStartUpload(t, repo, "up-"+id, newTestSecret(id, now.Add(time.Hour)), now.Add(-time.Minute), now.Add(-time.Hour))
	}

	// A complete holds the upload's row lock while finalize runs.
	lockRow(t, "SELECT 1 FROM uploads WHERE session_id = 'up-locked' FOR UPDATE")

	n, err := repo.AbandonExpiredUploads(context.Background(), now, testBatchSize)
	if err != nil {
		t.Fatalf("abandon expired uploads: %v", err)
	}
	if n != 1 {
		t.Errorf("abandoned %d, want only the unlocked upload", n)
	}
	assertUploadState(t, repo, "up-free", domain.UploadAbandoned)
	assertUploadState(t, repo, "up-locked", domain.UploadUploading)
}

func TestCleanupRepo_DeleteFinishedUploads(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	longAgo := now.Add(-2 * time.Hour)

	for _, id := range []string{"old-done", "old-abandoned", "new-done", "new-abandoned", "stuck"} {
		mustStartUpload(t, repo, "up-"+id, newTestSecret(id, now.Add(time.Hour)), longAgo, longAgo)
	}
	mustComplete(t, repo, "up-old-done", longAgo)
	// Aborting keeps the parts; they go with the upload.
	mustRecordPart(t, repo, newTestUploadPart("up-old-abandoned", 1, 0, 1024))
	if err := repo.AbortUpload(ctx, "up-old-abandoned", longAgo); err != nil {
		t.Fatalf("abort old: %v", err)
	}
	mustComplete(t, repo, "up-new-done", now)
	if err := repo.AbortUpload(ctx, "up-new-abandoned", now); err != nil {
		t.Fatalf("abort new: %v", err)
	}
	// up-stuck is still uploading, long past its expiry: it is the expiry
	// sweep's, never this one's.

	n, err := repo.DeleteFinishedUploads(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("delete finished uploads: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted %d uploads, want the two old ones", n)
	}
	for _, id := range []string{"up-old-done", "up-old-abandoned"} {
		if _, _, err := repo.GetUpload(ctx, id); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: err = %v, want deleted", id, err)
		}
	}
	if parts := countRows(t, pool, "SELECT count(*) FROM upload_parts WHERE session_id = 'up-old-abandoned'"); parts != 0 {
		t.Errorf("deleted upload left %d parts", parts)
	}
	assertUploadState(t, repo, "up-new-done", domain.UploadCompleted)
	assertUploadState(t, repo, "up-new-abandoned", domain.UploadAbandoned)
	assertUploadState(t, repo, "up-stuck", domain.UploadUploading)

	// The upload goes, the secret it created stays.
	if got := mustGetSecret(t, repo, "old-done"); got.State != domain.SecretLive {
		t.Errorf("secret of a deleted upload: state = %q, want live", got.State)
	}
}

func TestCleanupRepo_ReleaseDrainedSecrets(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())

	for _, id := range []string{"drained", "draining"} {
		secret := newTestSecret(id, now.Add(time.Hour))
		secret.BurnAfterRead = true
		mustCreate(t, repo, secret)
	}
	// openAs gives sessions 15 minutes: one ended, one still runs.
	mustOpen(t, repo, "drained", "drained-opener", false, now.Add(-time.Hour))
	mustOpen(t, repo, "draining", "draining-opener", false, now)
	// A reusable secret's sessions do not matter; it is not ended.
	mustCreate(t, repo, newTestSecret("reusable", now.Add(time.Hour)))
	mustOpen(t, repo, "reusable", "recipient", false, now.Add(-time.Hour))
	// A deleted secret has nothing left to release.
	mustCreate(t, repo, newTestSecret("deleted", now.Add(time.Hour)))
	if err := repo.Delete(ctx, "deleted", now.Add(-time.Hour)); err != nil {
		t.Fatalf("delete: %v", err)
	}

	n, err := repo.ReleaseDrainedSecrets(ctx, now, testBatchSize)
	if err != nil {
		t.Fatalf("release drained secrets: %v", err)
	}
	if n != 1 {
		t.Errorf("released %d secrets, want 1", n)
	}
	drained := mustGetSecret(t, repo, "drained")
	assertEnded(t, drained, domain.OutcomeOpened)
	if drained.StorageKey != "" {
		t.Errorf("drained secret keeps storage key %q", drained.StorageKey)
	}
	assertDoomed(t, pool, domain.UploadStorageKey(uploadSessionOf("drained")), now)

	draining := mustGetSecret(t, repo, "draining")
	if draining.StorageKey == "" {
		t.Error("a secret with a running download lost its object")
	}
	assertNotDoomed(t, pool, draining.StorageKey)
	assertNotDoomed(t, pool, domain.UploadStorageKey(uploadSessionOf("reusable")))

	// Once the last session ends, the object goes and so does the download.
	later := now.Add(15 * time.Minute)
	if n, err := repo.ReleaseDrainedSecrets(ctx, later, testBatchSize); err != nil || n != 1 {
		t.Errorf("release after the session ended = %d, %v; want 1", n, err)
	}
	assertDoomed(t, pool, draining.StorageKey, later)
	if _, err := download(repo, "draining", "draining-opener", now); !errors.Is(err, domain.ErrForbidden) {
		t.Errorf("download after release: err = %v, want ErrForbidden", err)
	}
}

func TestCleanupRepo_ReleaseDrainedSecretsInBatches(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	for _, id := range []string{"a", "b", "c"} {
		secret := newTestSecret(id, now.Add(time.Hour))
		secret.BurnAfterRead = true
		mustCreate(t, repo, secret)
		mustOpen(t, repo, id, "opener-"+id, false, now.Add(-time.Hour))
	}

	if n, err := repo.ReleaseDrainedSecrets(ctx, now, 2); err != nil || n != 2 {
		t.Errorf("first batch = %d, %v; want 2", n, err)
	}
	if n, err := repo.ReleaseDrainedSecrets(ctx, now, 2); err != nil || n != 1 {
		t.Errorf("second batch = %d, %v; want 1", n, err)
	}
	if n, err := repo.ReleaseDrainedSecrets(ctx, now, 2); err != nil || n != 0 {
		t.Errorf("third batch = %d, %v; want 0", n, err)
	}
}

func TestCleanupRepo_DeleteExpiredSecrets(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	expired := now.Add(-time.Minute)
	keyOf := func(id string) string { return domain.UploadStorageKey(uploadSessionOf(id)) }

	mustCreate(t, repo, newTestSecret("live-expired", expired))
	mustOpen(t, repo, "live-expired", "recipient", false, expired.Add(-time.Hour))
	mustCreate(t, repo, newTestSecret("deleted-expired", expired))
	if err := repo.Delete(ctx, "deleted-expired", expired.Add(-time.Hour)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	opened := newTestSecret("opened-expired", expired)
	opened.BurnAfterRead = true
	mustCreate(t, repo, opened)
	mustOpen(t, repo, "opened-expired", "opened-opener", false, expired.Add(-time.Minute))
	// The expiry is inclusive here: a secret is gone at the moment it expires.
	mustCreate(t, repo, newTestSecret("at-expiry", now))
	mustCreate(t, repo, newTestSecret("live", now.Add(time.Hour)))
	// An upload under way is left to the upload's own expiry.
	mustStartUpload(t, repo, "up-uploading-expired", newTestSecret("uploading-expired", expired), now.Add(time.Hour), expired.Add(-time.Hour))

	n, err := repo.DeleteExpiredSecrets(ctx, now, testBatchSize)
	if err != nil {
		t.Fatalf("delete expired secrets: %v", err)
	}
	if n != 4 {
		t.Errorf("deleted %d secrets, want 4", n)
	}
	for _, id := range []string{"live-expired", "deleted-expired", "opened-expired", "at-expiry"} {
		assertSecretGone(t, repo, id)
	}
	// Nothing about them is kept, their sessions included.
	if sessions := countRows(t, pool, "SELECT count(*) FROM retrieval_sessions"); sessions != 0 {
		t.Errorf("expired secrets left %d retrieval sessions", sessions)
	}
	// Objects they still held are doomed now; the deleted one's was already.
	for _, id := range []string{"live-expired", "opened-expired", "at-expiry"} {
		assertDoomed(t, pool, keyOf(id), now)
	}
	assertDoomed(t, pool, keyOf("deleted-expired"), expired.Add(-time.Hour))

	if got := mustGetSecret(t, repo, "live"); got.State != domain.SecretLive {
		t.Errorf("unexpired secret: state = %q, want live", got.State)
	}
	assertNotDoomed(t, pool, keyOf("live"))
	if got := mustGetSecret(t, repo, "uploading-expired"); got.State != domain.SecretUploading {
		t.Errorf("uploading secret: state = %q, want uploading", got.State)
	}
	assertNotDoomed(t, pool, "blobs/up-uploading-expired")

	// The completed upload outlives its secret until it is deleted itself.
	upload, _ := mustGetUpload(t, repo, uploadSessionOf("live-expired"))
	if upload.State != domain.UploadCompleted || upload.PublicID != "" || upload.StorageKey != "" {
		t.Errorf("upload of an expired secret = %+v, want completed without its secret", upload)
	}
}

func TestCleanupRepo_DeleteExpiredSecretsInBatchesOldestFirst(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	for _, tc := range []struct {
		id  string
		ago time.Duration
	}{{"1h", time.Hour}, {"3h", 3 * time.Hour}, {"2h", 2 * time.Hour}} {
		mustCreate(t, repo, newTestSecret(tc.id, now.Add(-tc.ago)))
	}

	if n, err := repo.DeleteExpiredSecrets(ctx, now, 2); err != nil || n != 2 {
		t.Fatalf("first batch = %d, %v; want 2", n, err)
	}
	assertSecretGone(t, repo, "3h")
	assertSecretGone(t, repo, "2h")
	mustGetSecret(t, repo, "1h")

	if n, err := repo.DeleteExpiredSecrets(ctx, now, 2); err != nil || n != 1 {
		t.Errorf("second batch = %d, %v; want 1", n, err)
	}
	assertSecretGone(t, repo, "1h")
}

func TestCleanupRepo_DeleteExpiredSecretsSkipsLockedRows(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	for _, id := range []string{"locked", "free"} {
		mustCreate(t, repo, newTestSecret(id, now.Add(-time.Minute)))
	}

	lockRow(t, "SELECT 1 FROM secrets WHERE public_id = 'locked' FOR UPDATE")

	n, err := repo.DeleteExpiredSecrets(context.Background(), now, testBatchSize)
	if err != nil {
		t.Fatalf("delete expired secrets: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted %d, want only the unlocked secret", n)
	}
	assertSecretGone(t, repo, "free")
	mustGetSecret(t, repo, "locked")
	assertNotDoomed(t, pool, domain.UploadStorageKey(uploadSessionOf("locked")))
}

func TestCleanupRepo_DeleteDoomedObjects(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())

	// Doomed in three ways, at distinct moments so the order is known.
	mustCreate(t, repo, newTestSecret("deleted", now.Add(time.Hour)))
	if err := repo.Delete(ctx, "deleted", now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mustStartUpload(t, repo, "up-aborted", newTestSecret("aborted", now.Add(time.Hour)), now.Add(time.Hour), now.Add(-time.Hour))
	if err := repo.RecordS3UploadID(ctx, "blobs/up-aborted", "s3-aborted"); err != nil {
		t.Fatalf("record s3 upload id: %v", err)
	}
	if err := repo.AbortUpload(ctx, "up-aborted", now.Add(-3*time.Minute)); err != nil {
		t.Fatalf("abort: %v", err)
	}
	mustCreate(t, repo, newTestSecret("expired", now.Add(-time.Hour)))
	if _, err := repo.DeleteExpiredSecrets(ctx, now.Add(-time.Minute), testBatchSize); err != nil {
		t.Fatalf("delete expired secrets: %v", err)
	}
	mustCreate(t, repo, newTestSecret("live", now.Add(time.Hour)))

	var got []domain.Object
	batch, err := repo.DeleteDoomedObjects(ctx, time.Now(), testBatchSize, func(object *domain.Object) error {
		got = append(got, *object)
		return nil
	})
	if err != nil {
		t.Fatalf("delete doomed objects: %v", err)
	}
	if batch != (domain.CleanupBatch{Found: 3, Removed: 3}) {
		t.Errorf("batch = %+v, want 3 found and removed", batch)
	}
	keys := make([]string, 0, len(got))
	for _, o := range got {
		keys = append(keys, o.StorageKey)
	}
	want := []string{"blobs/up-aborted", domain.UploadStorageKey(uploadSessionOf("deleted")), domain.UploadStorageKey(uploadSessionOf("expired"))}
	if !slices.Equal(keys, want) {
		t.Errorf("removed %v, want oldest doomed first: %v", keys, want)
	}
	// remove gets what storage needs to delete the object, an open multipart
	// upload included.
	if len(got) > 0 {
		aborted := got[0]
		if aborted.State != domain.ObjectWriting || aborted.S3UploadID != "s3-aborted" || aborted.DoomedAt == nil || !aborted.DoomedAt.Equal(now.Add(-3*time.Minute)) {
			t.Errorf("aborted upload's object = %+v, want writing with its s3 upload id", aborted)
		}
	}
	if len(got) > 1 && got[1].State != domain.ObjectStored {
		t.Errorf("deleted secret's object state = %q, want stored", got[1].State)
	}
	for _, key := range want {
		if getObject(t, pool, key) != nil {
			t.Errorf("object %s is still in the ledger", key)
		}
	}
	assertNotDoomed(t, pool, domain.UploadStorageKey(uploadSessionOf("live")))

	if batch, err := repo.DeleteDoomedObjects(ctx, time.Now(), testBatchSize, removeAll(new([]string))); err != nil || batch != (domain.CleanupBatch{}) {
		t.Errorf("second run = %+v, %v; want nothing left", batch, err)
	}
}

func TestCleanupRepo_DeleteDoomedObjectsKeepsTheOnesStorageFailedFor(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	for _, id := range []string{"stuck", "ok"} {
		mustCreate(t, repo, newTestSecret(id, now.Add(time.Hour)))
		if err := repo.Delete(ctx, id, now); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}
	stuckKey := domain.UploadStorageKey(uploadSessionOf("stuck"))

	tried := moment(time.Now())
	batch, err := repo.DeleteDoomedObjects(ctx, tried, testBatchSize, func(object *domain.Object) error {
		if object.StorageKey == stuckKey {
			return errors.New("storage unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("delete doomed objects: %v", err)
	}
	// The row stays, so the next cycle tries again instead of leaving the
	// object in storage with nobody knowing about it.
	if batch != (domain.CleanupBatch{Found: 2, Removed: 1}) {
		t.Errorf("batch = %+v, want 2 found, 1 removed", batch)
	}
	assertDoomed(t, pool, stuckKey, now)
	if attempted := mustGetObject(t, pool, stuckKey).AttemptedAt; attempted == nil || !attempted.Equal(tried) {
		t.Errorf("attempted_at = %v, want the failed try, %v", attempted, tried)
	}
	if getObject(t, pool, domain.UploadStorageKey(uploadSessionOf("ok"))) != nil {
		t.Error("removed object is still in the ledger")
	}

	var seen []string
	if batch, err := repo.DeleteDoomedObjects(ctx, time.Now(), testBatchSize, removeAll(&seen)); err != nil || batch != (domain.CleanupBatch{Found: 1, Removed: 1}) {
		t.Errorf("retry = %+v, %v; want the kept object removed", batch, err)
	}
	if !slices.Equal(seen, []string{stuckKey}) {
		t.Errorf("retry removed %v, want %s", seen, stuckKey)
	}
}

func TestCleanupRepo_DeleteDoomedObjectsTriesUntriedOnesFirst(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	// Doomed oldest first: stuck, then next, then last.
	for i, id := range []string{"stuck", "next", "last"} {
		mustCreate(t, repo, newTestSecret(id, now.Add(time.Hour)))
		if err := repo.Delete(ctx, id, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}
	key := func(id string) string { return domain.UploadStorageKey(uploadSessionOf(id)) }
	refuse := func(object *domain.Object) error {
		if object.StorageKey == key("stuck") {
			return errors.New("storage refuses this one")
		}
		return nil
	}

	// One object per batch: the oldest fails, and the next batches take the
	// ones not tried yet before trying it again, so an object storage keeps
	// refusing cannot hold up the rest.
	var order []string
	for range 4 {
		if _, err := repo.DeleteDoomedObjects(ctx, now.Add(time.Minute), 1, func(object *domain.Object) error {
			order = append(order, object.StorageKey)
			return refuse(object)
		}); err != nil {
			t.Fatalf("delete doomed objects: %v", err)
		}
	}
	if want := []string{key("stuck"), key("next"), key("last"), key("stuck")}; !slices.Equal(order, want) {
		t.Errorf("tried %v, want %v", order, want)
	}
	if left := countRows(t, pool, "SELECT count(*) FROM objects"); left != 1 {
		t.Errorf("objects left = %d, want only the refused one", left)
	}
}

func TestCleanupRepo_DeleteDoomedObjectsInBatches(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	for i, id := range []string{"a", "b", "c"} {
		mustCreate(t, repo, newTestSecret(id, now.Add(time.Hour)))
		if err := repo.Delete(ctx, id, now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}

	var seen []string
	if batch, err := repo.DeleteDoomedObjects(ctx, time.Now(), 2, removeAll(&seen)); err != nil || batch != (domain.CleanupBatch{Found: 2, Removed: 2}) {
		t.Errorf("first batch = %+v, %v; want 2", batch, err)
	}
	if batch, err := repo.DeleteDoomedObjects(ctx, time.Now(), 2, removeAll(&seen)); err != nil || batch != (domain.CleanupBatch{Found: 1, Removed: 1}) {
		t.Errorf("second batch = %+v, %v; want 1", batch, err)
	}
	want := []string{
		domain.UploadStorageKey(uploadSessionOf("a")),
		domain.UploadStorageKey(uploadSessionOf("b")),
		domain.UploadStorageKey(uploadSessionOf("c")),
	}
	if !slices.Equal(seen, want) {
		t.Errorf("removed %v, want %v", seen, want)
	}
}

func TestCleanupRepo_DeleteDoomedObjectsLeavesObjectsASecretStillHolds(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustCreate(t, repo, newTestSecret("held", now.Add(time.Hour)))
	key := domain.UploadStorageKey(uploadSessionOf("held"))

	// Every business change clears the secret's key when it dooms the object.
	// Should one ever not, the sweep must not delete from under the secret.
	if _, err := pool.Exec(ctx, "UPDATE objects SET doomed_at = $2 WHERE storage_key = $1", key, now); err != nil {
		t.Fatalf("doom held object: %v", err)
	}

	batch, err := repo.DeleteDoomedObjects(ctx, time.Now(), testBatchSize, func(*domain.Object) error {
		t.Error("remove ran for an object a secret still holds")
		return nil
	})
	if err != nil {
		t.Fatalf("delete doomed objects: %v", err)
	}
	if batch != (domain.CleanupBatch{}) {
		t.Errorf("batch = %+v, want nothing found", batch)
	}
	mustGetObject(t, pool, key)
	if _, err := openAs(repo, "held", "recipient", false, now); err != nil {
		t.Errorf("open held secret: %v", err)
	}
}

// TestCleanupRepo_NothingOutlivesASecret runs a secret through each way it
// can end and the whole cleanup after it, and checks that no row is left.
func TestCleanupRepo_NothingOutlivesASecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(t *testing.T, repo *pgadapter.SecretRepo, now time.Time)
	}{
		{"opened one-time", func(t *testing.T, repo *pgadapter.SecretRepo, now time.Time) {
			mustOpen(t, repo, "whole", "opener", false, now)
		}},
		{"deleted", func(t *testing.T, repo *pgadapter.SecretRepo, now time.Time) {
			mustOpen(t, repo, "whole", "opener", false, now)
			if err := repo.Delete(context.Background(), "whole", now); err != nil {
				t.Fatalf("delete: %v", err)
			}
		}},
		{"expired", func(*testing.T, *pgadapter.SecretRepo, time.Time) {}},
		{"aborted", nil},
		{"upload ran out", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := setupTestDB(t)
			repo := pgadapter.NewSecretRepo(pool)
			ctx := context.Background()
			now := moment(time.Now())

			secret := newTestSecret("whole", now.Add(time.Hour))
			secret.BurnAfterRead = tc.name == "opened one-time"
			mustStartUpload(t, repo, "up-whole", secret, now.Add(10*time.Minute), now)
			if err := repo.RecordS3UploadID(ctx, "blobs/up-whole", "s3-whole"); err != nil {
				t.Fatalf("record s3 upload id: %v", err)
			}
			mustRecordPart(t, repo, newTestUploadPart("up-whole", 1, 0, 1024))
			switch tc.name {
			case "aborted":
				if err := repo.AbortUpload(ctx, "up-whole", now); err != nil {
					t.Fatalf("abort: %v", err)
				}
			case "upload ran out":
			default:
				mustComplete(t, repo, "up-whole", now)
				tc.end(t, repo, now)
			}

			// One cleanup cycle long after the secret's expiry, in the order
			// the cleanup runs its sweeps.
			later := now.Add(2 * time.Hour)
			var removed []string
			steps := []struct {
				name string
				run  func() error
			}{
				{"retrieval sessions", func() error { _, err := repo.DeleteExpiredRetrievalSessions(ctx, later); return err }},
				{"expired uploads", func() error { _, err := repo.AbandonExpiredUploads(ctx, later, testBatchSize); return err }},
				{"finished uploads", func() error { _, err := repo.DeleteFinishedUploads(ctx, later.Add(-time.Hour)); return err }},
				{"drained secrets", func() error { _, err := repo.ReleaseDrainedSecrets(ctx, later, testBatchSize); return err }},
				{"expired secrets", func() error { _, err := repo.DeleteExpiredSecrets(ctx, later, testBatchSize); return err }},
				{"doomed objects", func() error {
					_, err := repo.DeleteDoomedObjects(ctx, time.Now(), testBatchSize, removeAll(&removed))
					return err
				}},
			}
			for _, step := range steps {
				if err := step.run(); err != nil {
					t.Fatalf("%s: %v", step.name, err)
				}
			}

			// The upload ended within the cycle; it is kept an hour for a
			// repeated complete or abort, then goes too.
			if _, err := repo.DeleteFinishedUploads(ctx, later.Add(time.Hour)); err != nil {
				t.Fatalf("finished uploads an hour later: %v", err)
			}

			if !slices.Equal(removed, []string{"blobs/up-whole"}) {
				t.Errorf("removed from storage %v, want blobs/up-whole exactly once", removed)
			}
			for _, table := range []string{"objects", "secrets", "uploads", "upload_parts", "retrieval_sessions"} {
				if n := countRows(t, pool, "SELECT count(*) FROM "+table); n != 0 {
					t.Errorf("%s keeps %d rows", table, n)
				}
			}
			// And the public id can be used again.
			fresh := newTestSecret("whole", later.Add(time.Hour))
			fresh.MetadataTokenHash = tokencrypto.TokenHash("a new link")
			mustStartUpload(t, repo, "up-whole-again", fresh, later.Add(time.Hour), later)
		})
	}
}
