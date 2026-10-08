package postgres_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pgadapter "github.com/secretli/server/internal/adapter/postgres"
	"github.com/secretli/server/internal/domain"
	tokencrypto "github.com/secretli/server/internal/platform/crypto"
)

func newTestUploadPart(sessionID string, number int, offset, size int64) *domain.UploadPart {
	return &domain.UploadPart{
		SessionID:  sessionID,
		PartNumber: number,
		Offset:     offset,
		Size:       size,
		SHA256:     "sha-" + sessionID,
		ETag:       "etag-" + sessionID,
		CreatedAt:  time.Now(),
	}
}

func mustRecordPart(t *testing.T, repo *pgadapter.SecretRepo, part *domain.UploadPart) {
	t.Helper()
	if _, err := repo.RecordUploadPart(context.Background(), part); err != nil {
		t.Fatalf("record part %d of %s: %v", part.PartNumber, part.SessionID, err)
	}
}

func mustGetUpload(t *testing.T, repo *pgadapter.SecretRepo, sessionID string) (*domain.Upload, []domain.UploadPart) {
	t.Helper()
	upload, parts, err := repo.GetUpload(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("get upload %s: %v", sessionID, err)
	}
	return upload, parts
}

func assertUploadState(t *testing.T, repo *pgadapter.SecretRepo, sessionID string, want domain.UploadState) {
	t.Helper()
	if got, _ := mustGetUpload(t, repo, sessionID); got.State != want {
		t.Errorf("upload %s state = %q, want %q", sessionID, got.State, want)
	}
}

func noopFinalize(*domain.Upload, []domain.UploadPart) error { return nil }

func noFinalize(t *testing.T) func(*domain.Upload, []domain.UploadPart) error {
	return func(*domain.Upload, []domain.UploadPart) error {
		t.Error("finalize must not run")
		return nil
	}
}

func TestUploadRepo_StartUploadFilesTheSecretTheUploadAndTheObject(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	secretExpiresAt := moment(now.Add(24 * time.Hour))
	uploadExpiresAt := moment(now.Add(time.Hour))

	mustStartUpload(t, repo, "up-start", newTestSecret("start", secretExpiresAt), uploadExpiresAt, now)

	if got := mustGetSecret(t, repo, "start"); got.State != domain.SecretUploading || got.StorageKey != "blobs/up-start" {
		t.Errorf("secret state = %q, storage key = %q; want uploading into blobs/up-start", got.State, got.StorageKey)
	}

	// The object is known before anything is written under its key.
	object := mustGetObject(t, pool, "blobs/up-start")
	if object.State != string(domain.ObjectWriting) || object.S3UploadID != nil || object.DoomedAt != nil || !object.CreatedAt.Equal(now) {
		t.Errorf("object = %+v, want writing since %v, without upload id, not doomed", object, now)
	}

	upload, parts := mustGetUpload(t, repo, "up-start")
	want := domain.Upload{
		SessionID:       "up-start",
		PublicID:        "start",
		UploadTokenHash: tokencrypto.TokenHash("upload-token-up-start"),
		State:           domain.UploadUploading,
		StorageKey:      "blobs/up-start",
		BlobSize:        1024,
	}
	gotFields := *upload
	gotFields.ExpiresAt, gotFields.SecretExpiresAt = time.Time{}, time.Time{}
	if gotFields != want {
		t.Errorf("upload = %+v, want %+v", gotFields, want)
	}
	if !upload.ExpiresAt.Equal(uploadExpiresAt) || !upload.SecretExpiresAt.Equal(secretExpiresAt) {
		t.Errorf("upload expires %v, secret expires %v; want %v and %v",
			upload.ExpiresAt, upload.SecretExpiresAt, uploadExpiresAt, secretExpiresAt)
	}
	if len(parts) != 0 {
		t.Errorf("parts = %v, want none", parts)
	}
}

func TestUploadRepo_StartUploadRefusesATakenPublicID(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())

	mustStartUpload(t, repo, "up-taken-uploading", newTestSecret("taken-uploading", now.Add(time.Hour)), now.Add(time.Hour), now)
	mustCreate(t, repo, newTestSecret("taken-live", now.Add(time.Hour)))
	mustCreate(t, repo, newTestSecret("taken-deleted", now.Add(time.Hour)))
	if err := repo.Delete(ctx, "taken-deleted", now); err != nil {
		t.Fatalf("delete: %v", err)
	}
	burned := newTestSecret("taken-opened", now.Add(time.Hour))
	burned.BurnAfterRead = true
	mustCreate(t, repo, burned)
	mustOpen(t, repo, "taken-opened", "opener", false, now)
	// Expired but not yet cleaned up still counts as taken.
	mustCreate(t, repo, newTestSecret("taken-expired", now.Add(-time.Minute)))

	for _, id := range []string{"taken-uploading", "taken-live", "taken-deleted", "taken-opened", "taken-expired"} {
		sessionID := "up-again-" + id
		secret := newTestSecret(id, now.Add(time.Hour))
		err := repo.StartUpload(ctx, secret, newTestUpload(sessionID, secret, now.Add(time.Hour)), now)
		if !errors.Is(err, domain.ErrDuplicate) {
			t.Errorf("%s: err = %v, want ErrDuplicate", id, err)
		}
		// Nothing of the refused upload was written.
		if getObject(t, pool, domain.UploadStorageKey(sessionID)) != nil {
			t.Errorf("%s: the refused upload's object is in the ledger", id)
		}
		if _, _, err := repo.GetUpload(ctx, sessionID); !errors.Is(err, domain.ErrNotFound) {
			t.Errorf("%s: refused upload: err = %v, want ErrNotFound", id, err)
		}
	}
}

func TestUploadRepo_RecordS3UploadIDWhileTheObjectIsWritten(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-s3", newTestSecret("s3", now.Add(time.Hour)), now.Add(time.Hour), now)

	if err := repo.RecordS3UploadID(ctx, "blobs/up-s3", "s3-upload-1"); err != nil {
		t.Fatalf("record: %v", err)
	}
	if upload, _ := mustGetUpload(t, repo, "up-s3"); upload.S3UploadID != "s3-upload-1" {
		t.Errorf("upload's s3 upload id = %q, want s3-upload-1", upload.S3UploadID)
	}
	if err := repo.RecordS3UploadID(ctx, "blobs/unknown", "s3-upload-2"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown object: err = %v, want ErrNotFound", err)
	}

	// A stored object has no multipart upload left to record.
	mustComplete(t, repo, "up-s3", now)
	if err := repo.RecordS3UploadID(ctx, "blobs/up-s3", "s3-upload-3"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("stored object: err = %v, want ErrNotFound", err)
	}
	if object := mustGetObject(t, pool, "blobs/up-s3"); object.S3UploadID == nil || *object.S3UploadID != "s3-upload-1" {
		t.Errorf("s3 upload id = %v, want s3-upload-1 kept", object.S3UploadID)
	}
}

func TestUploadRepo_GetUploadOfAnUnknownSession(t *testing.T) {
	repo := pgadapter.NewSecretRepo(setupTestDB(t))
	if _, _, err := repo.GetUpload(context.Background(), "unknown"); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestUploadRepo_RecordUploadPart(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-parts", newTestSecret("parts", now.Add(time.Hour)), now.Add(time.Hour), now)

	mustRecordPart(t, repo, newTestUploadPart("up-parts", 2, 512, 512))
	first := newTestUploadPart("up-parts", 1, 0, 512)
	first.CreatedAt = now
	got, err := repo.RecordUploadPart(ctx, first)
	if err != nil {
		t.Fatalf("record part 1: %v", err)
	}
	if got.SessionID != "up-parts" || got.PartNumber != 1 || got.Offset != 0 || got.Size != 512 ||
		got.SHA256 != "sha-up-parts" || got.ETag != "etag-up-parts" || !got.CreatedAt.Equal(now) {
		t.Errorf("recorded part = %+v, want part 1 as given", got)
	}

	// The same part again is a retry and returns what was recorded.
	retry := newTestUploadPart("up-parts", 1, 0, 512)
	retry.ETag = "etag-retry"
	got, err = repo.RecordUploadPart(ctx, retry)
	if err != nil {
		t.Fatalf("retry part 1: %v", err)
	}
	if got.ETag != "etag-up-parts" {
		t.Errorf("retry etag = %q, want the first one kept", got.ETag)
	}

	// A different part under the same number is a conflict.
	for name, part := range map[string]*domain.UploadPart{
		"offset": newTestUploadPart("up-parts", 1, 1, 512),
		"size":   newTestUploadPart("up-parts", 1, 0, 511),
		"sha":    {SessionID: "up-parts", PartNumber: 1, Offset: 0, Size: 512, SHA256: "other", ETag: "e", CreatedAt: now},
	} {
		if _, err := repo.RecordUploadPart(ctx, part); !errors.Is(err, domain.ErrConflict) {
			t.Errorf("different %s: err = %v, want ErrConflict", name, err)
		}
	}

	_, parts := mustGetUpload(t, repo, "up-parts")
	if len(parts) != 2 || parts[0].PartNumber != 1 || parts[1].PartNumber != 2 {
		t.Errorf("parts = %+v, want parts 1 and 2 in order", parts)
	}

	// Clearing lets the client upload every part again.
	if err := repo.ClearUploadParts(ctx, "up-parts"); err != nil {
		t.Fatalf("clear parts: %v", err)
	}
	if _, parts := mustGetUpload(t, repo, "up-parts"); len(parts) != 0 {
		t.Errorf("parts after clear = %+v, want none", parts)
	}
	mustRecordPart(t, repo, newTestUploadPart("up-parts", 1, 0, 1024))
}

func TestUploadRepo_CompleteMakesTheSecretLive(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-done", newTestSecret("done", now.Add(time.Hour)), now.Add(time.Hour), now)
	if err := repo.RecordS3UploadID(ctx, "blobs/up-done", "s3-done"); err != nil {
		t.Fatalf("record s3 upload id: %v", err)
	}
	mustRecordPart(t, repo, newTestUploadPart("up-done", 2, 512, 512))
	mustRecordPart(t, repo, newTestUploadPart("up-done", 1, 0, 512))

	completedAt := moment(now.Add(time.Minute))
	var finalized []domain.UploadPart
	upload, err := repo.CompleteUpload(ctx, "up-done", completedAt, func(u *domain.Upload, parts []domain.UploadPart) error {
		// finalize gets what it needs to assemble the object.
		if u.StorageKey != "blobs/up-done" || u.S3UploadID != "s3-done" || u.BlobSize != 1024 || u.State != domain.UploadUploading {
			t.Errorf("finalize got upload %+v, want the uploading upload with its object", u)
		}
		finalized = parts
		return nil
	})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if len(finalized) != 2 || finalized[0].PartNumber != 1 || finalized[1].PartNumber != 2 {
		t.Errorf("finalize got parts %+v, want 1 and 2 in order", finalized)
	}
	if upload.State != domain.UploadCompleted || upload.FinishedAt == nil || !upload.FinishedAt.Equal(completedAt) {
		t.Errorf("returned upload state = %q, finished at %v; want completed at %v", upload.State, upload.FinishedAt, completedAt)
	}

	secret := mustGetSecret(t, repo, "done")
	if secret.State != domain.SecretLive || secret.CreatedAt == nil || !secret.CreatedAt.Equal(completedAt) {
		t.Errorf("secret state = %q, created at %v; want live since %v", secret.State, secret.CreatedAt, completedAt)
	}
	if object := mustGetObject(t, pool, "blobs/up-done"); object.State != string(domain.ObjectStored) || object.DoomedAt != nil {
		t.Errorf("object = %+v, want stored", object)
	}
	stored, parts := mustGetUpload(t, repo, "up-done")
	if stored.State != domain.UploadCompleted || stored.FinishedAt == nil || !stored.FinishedAt.Equal(completedAt) || stored.PublicID != "done" {
		t.Errorf("stored upload = %+v, want completed at %v for done", stored, completedAt)
	}
	if len(parts) != 0 {
		t.Errorf("completed upload keeps %d parts, want 0", len(parts))
	}
	mustOpen(t, repo, "done", "first", false, completedAt)
}

func TestUploadRepo_RepeatedCompleteReturnsTheUploadWithoutFinalizing(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-twice", newTestSecret("twice", now.Add(time.Hour)), now.Add(time.Hour), now)
	mustComplete(t, repo, "up-twice", now)

	upload, err := repo.CompleteUpload(context.Background(), "up-twice", now.Add(time.Minute), noFinalize(t))
	if err != nil {
		t.Fatalf("repeated complete: %v", err)
	}
	if upload.State != domain.UploadCompleted || upload.PublicID != "twice" || upload.FinishedAt == nil || !upload.FinishedAt.Equal(now) {
		t.Errorf("repeated complete = %+v, want the upload completed at %v", upload, now)
	}
	if secret := mustGetSecret(t, repo, "twice"); secret.CreatedAt == nil || !secret.CreatedAt.Equal(now) {
		t.Errorf("secret created at %v, want %v unchanged", secret.CreatedAt, now)
	}
}

func TestUploadRepo_ConcurrentCompletesFinalizeOnce(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-race", newTestSecret("race", now.Add(time.Hour)), now.Add(time.Hour), now)

	const callers = 5
	var finalizeCalls atomic.Int32
	errs := make([]error, callers)
	states := make([]domain.UploadState, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			upload, err := repo.CompleteUpload(context.Background(), "up-race", now, func(*domain.Upload, []domain.UploadPart) error {
				finalizeCalls.Add(1)
				// Hold the lock long enough for the other callers to queue.
				time.Sleep(50 * time.Millisecond)
				return nil
			})
			errs[i] = err
			if upload != nil {
				states[i] = upload.State
			}
		})
	}
	wg.Wait()

	if got := finalizeCalls.Load(); got != 1 {
		t.Errorf("finalize ran %d times, want exactly 1", got)
	}
	for i := range callers {
		if errs[i] != nil || states[i] != domain.UploadCompleted {
			t.Errorf("caller %d: state = %q, err = %v; want completed", i, states[i], errs[i])
		}
	}
}

func TestUploadRepo_CompleteRollsBackWhenFinalizeFails(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-fail", newTestSecret("fail", now.Add(time.Hour)), now.Add(time.Hour), now)
	mustRecordPart(t, repo, newTestUploadPart("up-fail", 1, 0, 1024))

	wantErr := errors.New("storage rejected parts")
	_, err := repo.CompleteUpload(ctx, "up-fail", now, func(*domain.Upload, []domain.UploadPart) error { return wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want finalize's error", err)
	}

	// Nothing moved, so the client can fix the parts and complete again.
	if secret := mustGetSecret(t, repo, "fail"); secret.State != domain.SecretUploading || secret.CreatedAt != nil {
		t.Errorf("secret state = %q, created at %v; want still uploading", secret.State, secret.CreatedAt)
	}
	if object := mustGetObject(t, pool, "blobs/up-fail"); object.State != string(domain.ObjectWriting) {
		t.Errorf("object state = %q, want writing", object.State)
	}
	upload, parts := mustGetUpload(t, repo, "up-fail")
	if upload.State != domain.UploadUploading || upload.FinishedAt != nil || len(parts) != 1 {
		t.Errorf("upload state = %q, finished at %v, %d parts; want uploading with its part", upload.State, upload.FinishedAt, len(parts))
	}

	mustComplete(t, repo, "up-fail", now)
	if secret := mustGetSecret(t, repo, "fail"); secret.State != domain.SecretLive {
		t.Errorf("after retry: state = %q, want live", secret.State)
	}
}

func TestUploadRepo_CompleteRefusesAnAbandonedUpload(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-gone", newTestSecret("gone", now.Add(time.Hour)), now.Add(time.Hour), now)
	if err := repo.AbortUpload(ctx, "up-gone", now); err != nil {
		t.Fatalf("abort: %v", err)
	}

	if _, err := repo.CompleteUpload(ctx, "up-gone", now, noFinalize(t)); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("abandoned: err = %v, want ErrConflict", err)
	}
	if _, err := repo.CompleteUpload(ctx, "unknown", now, noFinalize(t)); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown: err = %v, want ErrNotFound", err)
	}
}

func TestUploadRepo_AbortAbandonsTheUploadAndFreesThePublicID(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustStartUpload(t, repo, "up-abort", newTestSecret("abort", now.Add(time.Hour)), now.Add(time.Hour), now)
	mustRecordPart(t, repo, newTestUploadPart("up-abort", 1, 0, 1024))

	abortedAt := moment(now.Add(time.Minute))
	if err := repo.AbortUpload(ctx, "up-abort", abortedAt); err != nil {
		t.Fatalf("abort: %v", err)
	}

	// The secret never existed.
	assertSecretGone(t, repo, "abort")
	assertDoomed(t, pool, "blobs/up-abort", abortedAt)
	upload, _ := mustGetUpload(t, repo, "up-abort")
	if upload.State != domain.UploadAbandoned || upload.FinishedAt == nil || !upload.FinishedAt.Equal(abortedAt) {
		t.Errorf("upload state = %q, finished at %v; want abandoned at %v", upload.State, upload.FinishedAt, abortedAt)
	}
	if upload.PublicID != "" || upload.StorageKey != "" {
		t.Errorf("abandoned upload keeps public id %q, storage key %q; want both gone with the secret", upload.PublicID, upload.StorageKey)
	}

	// Aborting again is answered the same.
	if err := repo.AbortUpload(ctx, "up-abort", abortedAt.Add(time.Minute)); err != nil {
		t.Errorf("second abort: %v", err)
	}
	if again, _ := mustGetUpload(t, repo, "up-abort"); again.FinishedAt == nil || !again.FinishedAt.Equal(abortedAt) {
		t.Errorf("second abort moved finished at to %v, want %v", again.FinishedAt, abortedAt)
	}

	// The public id is free for a new upload, which writes its own object.
	mustStartUpload(t, repo, "up-abort-again", newTestSecret("abort", now.Add(time.Hour)), now.Add(time.Hour), now)
	if got := mustGetSecret(t, repo, "abort"); got.StorageKey != "blobs/up-abort-again" {
		t.Errorf("new secret's storage key = %q, want blobs/up-abort-again", got.StorageKey)
	}
	assertDoomed(t, pool, "blobs/up-abort", abortedAt)
	assertNotDoomed(t, pool, "blobs/up-abort-again")
}

func TestUploadRepo_AbortRefusesACompletedUpload(t *testing.T) {
	pool := setupTestDB(t)
	repo := pgadapter.NewSecretRepo(pool)
	ctx := context.Background()
	now := moment(time.Now())
	mustCreate(t, repo, newTestSecret("kept", now.Add(time.Hour)))

	if err := repo.AbortUpload(ctx, uploadSessionOf("kept"), now); !errors.Is(err, domain.ErrConflict) {
		t.Errorf("completed: err = %v, want ErrConflict", err)
	}
	if got := mustGetSecret(t, repo, "kept"); got.State != domain.SecretLive {
		t.Errorf("secret state = %q, want live", got.State)
	}
	assertNotDoomed(t, pool, domain.UploadStorageKey(uploadSessionOf("kept")))
	if err := repo.AbortUpload(ctx, "unknown", now); !errors.Is(err, domain.ErrNotFound) {
		t.Errorf("unknown: err = %v, want ErrNotFound", err)
	}
}
