package cleanup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/secretli/server/internal/adapter/metrics"
	"github.com/secretli/server/internal/domain"
)

func testMetrics() *metrics.SecretMetrics {
	return metrics.NewSecretMetrics(prometheus.NewRegistry())
}

// --- Mock implementations ---

var (
	_ Repo                      = (*mockRepo)(nil)
	_ domain.MultipartFileStore = (*mockFileStore)(nil)
)

// sqlStep is a database-only sweep that handles everything due in one call.
type sqlStep struct {
	err    error
	cutoff time.Time // what the last call was given
}

func (s *sqlStep) run(cutoff time.Time) (int64, error) {
	s.cutoff = cutoff
	return 0, s.err
}

// sqlBacklog is a database-only sweep that works in batches, like the
// database does: each call handles up to limit of the rows still due.
type sqlBacklog struct {
	due   int   // rows still due
	err   error // fails the call numbered errAt, or every call when errAt is 0
	errAt int
	// afterBatch runs at the end of every batch that did not fail, to end the
	// context in the middle of a backlog.
	afterBatch func()

	calls  int
	limits []int     // the limit of each call
	cutoff time.Time // what the last call was given
}

func (b *sqlBacklog) run(cutoff time.Time, limit int) (int, error) {
	b.calls++
	b.limits = append(b.limits, limit)
	b.cutoff = cutoff
	if b.err != nil && (b.errAt == 0 || b.errAt == b.calls) {
		return 0, b.err
	}
	n := min(limit, b.due)
	b.due -= n
	if b.afterBatch != nil {
		b.afterBatch()
	}
	return n, nil
}

// mockRepo is the database as the worker sees it. Its sweeps keep a backlog
// of what is due, and the object sweep a queue of doomed objects.
type mockRepo struct {
	retrievalSessions sqlStep
	abandonedUploads  sqlBacklog
	finishedUploads   sqlStep
	endedTransfers    sqlStep
	drainedSecrets    sqlBacklog
	expiredSecrets    sqlBacklog
	expiredPublicIDs  sqlBacklog

	// doomed is the doomed objects, oldest first. A batch takes up to limit of
	// them from the front, and those whose removal fails stay there, as their
	// rows do in the database.
	doomed           []*domain.Object
	doomedCalls      int
	doomedLimits     []int
	doomedErr        error // fails the call numbered doomedErrAt, or every call when that is 0
	doomedErrAt      int
	afterDoomedBatch func() // like sqlBacklog.afterBatch

	order []string          // the sweeps in the order they were called
	ctxs  []context.Context // the context of each call
}

// allSweeps is every sweep of the Repo, by the name the mock records.
var allSweeps = []string{
	"DeleteExpiredRetrievalSessions",
	"AbandonExpiredUploads",
	"DeleteFinishedUploads",
	"DeleteEndedTransfers",
	"DeleteDrainedSecrets",
	"DeleteExpiredSecrets",
	"DeleteExpiredPublicIDs",
	"DeleteDoomedObjects",
}

func (m *mockRepo) called(ctx context.Context, sweep string) {
	m.order = append(m.order, sweep)
	m.ctxs = append(m.ctxs, ctx)
}

func (m *mockRepo) DeleteExpiredRetrievalSessions(ctx context.Context, now time.Time) (int64, error) {
	m.called(ctx, "DeleteExpiredRetrievalSessions")
	return m.retrievalSessions.run(now)
}

func (m *mockRepo) AbandonExpiredUploads(ctx context.Context, now time.Time, limit int) (int, error) {
	m.called(ctx, "AbandonExpiredUploads")
	return m.abandonedUploads.run(now, limit)
}

func (m *mockRepo) DeleteFinishedUploads(ctx context.Context, finishedBefore time.Time) (int64, error) {
	m.called(ctx, "DeleteFinishedUploads")
	return m.finishedUploads.run(finishedBefore)
}

func (m *mockRepo) DeleteDrainedSecrets(ctx context.Context, now time.Time, limit int) (int, error) {
	m.called(ctx, "DeleteDrainedSecrets")
	return m.drainedSecrets.run(now, limit)
}

func (m *mockRepo) DeleteExpiredSecrets(ctx context.Context, now time.Time, limit int) (int, error) {
	m.called(ctx, "DeleteExpiredSecrets")
	return m.expiredSecrets.run(now, limit)
}

func (m *mockRepo) DeleteExpiredPublicIDs(ctx context.Context, now time.Time, limit int) (int, error) {
	m.called(ctx, "DeleteExpiredPublicIDs")
	return m.expiredPublicIDs.run(now, limit)
}

func (m *mockRepo) DeleteEndedTransfers(ctx context.Context, endedBefore time.Time) (int64, error) {
	m.called(ctx, "DeleteEndedTransfers")
	return m.endedTransfers.run(endedBefore)
}

func (m *mockRepo) DeleteDoomedObjects(ctx context.Context, limit int, remove func(*domain.Object) error) (domain.CleanupBatch, error) {
	m.called(ctx, "DeleteDoomedObjects")
	m.doomedCalls++
	m.doomedLimits = append(m.doomedLimits, limit)
	if m.doomedErr != nil && (m.doomedErrAt == 0 || m.doomedErrAt == m.doomedCalls) {
		return domain.CleanupBatch{}, m.doomedErr
	}
	batch := m.doomed[:min(limit, len(m.doomed))]
	var kept []*domain.Object
	for _, object := range batch {
		if err := remove(object); err != nil {
			kept = append(kept, object)
		}
	}
	// Like the database: objects whose removal failed count one more failed
	// removal and sink behind the rest.
	m.doomed = append(slices.Clone(m.doomed[len(batch):]), kept...)
	if m.afterDoomedBatch != nil {
		m.afterDoomedBatch()
	}
	return domain.CleanupBatch{Found: len(batch), Removed: len(batch) - len(kept)}, nil
}

// mockFileStore records every call, in order, as "<what> <key>". The worker
// only ever aborts the uploads under a key and deletes; a call to anything
// else shows up in calls.
type mockFileStore struct {
	calls []string
	ctxs  []context.Context

	deleteErr  error           // fails every delete
	abortErr   error           // fails every abort
	failDelete map[string]bool // keys whose delete fails
	failAbort  map[string]bool // keys whose abort fails
}

func (m *mockFileStore) record(ctx context.Context, call string) {
	m.calls = append(m.calls, call)
	m.ctxs = append(m.ctxs, ctx)
}

func (m *mockFileStore) Delete(ctx context.Context, key string) error {
	m.record(ctx, "delete "+key)
	if m.failDelete[key] {
		return errors.New("storage rejected delete")
	}
	return m.deleteErr
}

func (m *mockFileStore) AbortMultipartUploads(ctx context.Context, key string) error {
	m.record(ctx, "abort "+key)
	if m.failAbort[key] {
		return errors.New("storage rejected abort")
	}
	return m.abortErr
}

func (m *mockFileStore) GetRange(ctx context.Context, key string, _, _ int64) (io.ReadCloser, error) {
	m.record(ctx, "get-range "+key)
	return nil, nil
}

func (m *mockFileStore) CreateMultipartUpload(ctx context.Context, key string) (string, error) {
	m.record(ctx, "create-upload "+key)
	return "", nil
}

func (m *mockFileStore) UploadPart(ctx context.Context, key, _ string, _ int, _ io.Reader, _ int64) (string, error) {
	m.record(ctx, "upload-part "+key)
	return "", nil
}

func (m *mockFileStore) CompleteMultipartUpload(ctx context.Context, key, _ string, _ []domain.CompletedPart) error {
	m.record(ctx, "complete-upload "+key)
	return nil
}

func (m *mockFileStore) AbortMultipartUpload(ctx context.Context, key, uploadID string) error {
	m.record(ctx, "abort-by-id "+key+"#"+uploadID)
	return nil
}

// --- Fixtures ---

// batchedSweeps are the database-only sweeps that work in batches.
var batchedSweeps = []struct {
	name    string
	backlog func(*mockRepo) *sqlBacklog
}{
	{"expired uploads", func(r *mockRepo) *sqlBacklog { return &r.abandonedUploads }},
	{"drained secrets", func(r *mockRepo) *sqlBacklog { return &r.drainedSecrets }},
	{"expired secrets", func(r *mockRepo) *sqlBacklog { return &r.expiredSecrets }},
	{"expired public ids", func(r *mockRepo) *sqlBacklog { return &r.expiredPublicIDs }},
}

func writing(key string) *domain.Object {
	return &domain.Object{StorageKey: key, State: domain.ObjectWriting}
}

func stored(key string) *domain.Object {
	return &domain.Object{StorageKey: key, State: domain.ObjectStored}
}

// storedObjects makes n stored objects, keyed prefix0, prefix1 and so on.
func storedObjects(prefix string, n int) []*domain.Object {
	objects := make([]*domain.Object, 0, n)
	for _, key := range keys(prefix, n) {
		objects = append(objects, stored(key))
	}
	return objects
}

func objectKeys(objects []*domain.Object) []string {
	out := make([]string, 0, len(objects))
	for _, object := range objects {
		out = append(out, object.StorageKey)
	}
	return out
}

// --- Tests: what a cycle does ---

func TestRunCycle_RunsEverySweepWithItsCutoff(t *testing.T) {
	repo := &mockRepo{}
	store := &mockFileStore{}

	w := NewWorker(time.Minute, repo, store, testMetrics())
	before := time.Now()
	w.runCycle(context.Background())
	after := time.Now()

	if got, want := slices.Sorted(slices.Values(repo.order)), slices.Sorted(slices.Values(allSweeps)); !slices.Equal(got, want) {
		t.Errorf("sweeps run = %v, want each of %v once", repo.order, allSweeps)
	}

	// Everything is due as of the cycle's start. Finished uploads and ended
	// transfers are kept a while first.
	for _, c := range []struct {
		sweep     string
		cutoff    time.Time
		retention time.Duration
	}{
		{"expired retrieval sessions", repo.retrievalSessions.cutoff, 0},
		{"expired uploads", repo.abandonedUploads.cutoff, 0},
		{"finished uploads", repo.finishedUploads.cutoff, finishedUploadRetention},
		{"ended transfers", repo.endedTransfers.cutoff, endedTransferRetention},
		{"drained secrets", repo.drainedSecrets.cutoff, 0},
		{"expired secrets", repo.expiredSecrets.cutoff, 0},
		{"expired public ids", repo.expiredPublicIDs.cutoff, 0},
	} {
		if earliest, latest := before.Add(-c.retention), after.Add(-c.retention); c.cutoff.Before(earliest) || c.cutoff.After(latest) {
			t.Errorf("%s: cutoff %v, want the cycle's start less %v, between %v and %v", c.sweep, c.cutoff, c.retention, earliest, latest)
		}
	}

	// Batches are bounded, and only the object sweep touches storage.
	for _, c := range []struct {
		sweep  string
		limits []int
	}{
		{"expired uploads", repo.abandonedUploads.limits},
		{"drained secrets", repo.drainedSecrets.limits},
		{"expired secrets", repo.expiredSecrets.limits},
		{"expired public ids", repo.expiredPublicIDs.limits},
		{"doomed objects", repo.doomedLimits},
	} {
		if !slices.Equal(c.limits, []int{batchSize}) {
			t.Errorf("%s: batch limits %v, want one batch of %d", c.sweep, c.limits, batchSize)
		}
	}
	if len(store.calls) != 0 {
		t.Errorf("storage calls = %v, want none: nothing is doomed", store.calls)
	}
}

func TestRunCycle_RemovesObjectsAfterEverythingThatDoomsThem(t *testing.T) {
	repo := &mockRepo{doomed: []*domain.Object{stored("blobs/o")}}
	repo.abandonedUploads.due = 1
	repo.drainedSecrets.due = 1
	repo.expiredSecrets.due = 1

	w := NewWorker(time.Minute, repo, &mockFileStore{}, testMetrics())
	w.runCycle(context.Background())

	// What the cycle dooms is then gone by its end, not a cycle later.
	last := len(repo.order) - 1
	if repo.order[last] != "DeleteDoomedObjects" || slices.Contains(repo.order[:last], "DeleteDoomedObjects") {
		t.Errorf("sweeps ran in the order %v, want the object sweep once, and last", repo.order)
	}
}

func TestRunCycle_FreesPublicIDsAfterForgettingTheirSecrets(t *testing.T) {
	repo := &mockRepo{}
	w := NewWorker(time.Minute, repo, &mockFileStore{}, testMetrics())
	w.runCycle(context.Background())

	// A secret that expires is forgotten and its id freed in the same cycle.
	secrets, ids := slices.Index(repo.order, "DeleteExpiredSecrets"), slices.Index(repo.order, "DeleteExpiredPublicIDs")
	if secrets < 0 || ids < secrets {
		t.Errorf("sweeps ran in the order %v, want the public ids after the expired secrets", repo.order)
	}
}

func TestRunCycle_BoundsACycleWithATimeout(t *testing.T) {
	repo := &mockRepo{doomed: []*domain.Object{writing("blobs/w")}}
	store := &mockFileStore{}

	w := NewWorker(time.Minute, repo, store, testMetrics())
	before := time.Now()
	w.runCycle(context.Background())
	after := time.Now()

	// A hung database or storage call must not stall the cleanup for good: every
	// call, the storage ones too, carries the cycle's deadline.
	if len(repo.ctxs) != len(allSweeps) || len(store.ctxs) != 2 {
		t.Fatalf("%d sweeps and %d storage calls, want %d and 2 (abort and delete)", len(repo.ctxs), len(store.ctxs), len(allSweeps))
	}
	for i, ctx := range slices.Concat(repo.ctxs, store.ctxs) {
		deadline, ok := ctx.Deadline()
		if !ok || deadline.Before(before.Add(cycleTimeout)) || deadline.After(after.Add(cycleTimeout)) {
			t.Errorf("call %d: deadline %v (set: %t), want %v after the cycle's start", i+1, deadline, ok, cycleTimeout)
		}
	}
}

// --- Tests: the database-only sweeps ---

func TestRunCycle_DrainsFullBatchesAndStopsAtAShortOne(t *testing.T) {
	// A full batch may be followed by more, so it takes another call to learn
	// that there is nothing left.
	for _, sweep := range batchedSweeps {
		for _, size := range []struct{ due, calls int }{
			{due: 0, calls: 1},
			{due: 1, calls: 1},
			{due: batchSize - 1, calls: 1},
			{due: batchSize, calls: 2},
			{due: batchSize + 1, calls: 2},
			{due: 2*batchSize + 50, calls: 3},
			{due: 3 * batchSize, calls: 4},
		} {
			t.Run(fmt.Sprintf("%s/%d due", sweep.name, size.due), func(t *testing.T) {
				repo := &mockRepo{}
				backlog := sweep.backlog(repo)
				backlog.due = size.due
				store := &mockFileStore{}

				w := NewWorker(time.Minute, repo, store, testMetrics())
				w.runCycle(context.Background())

				if backlog.calls != size.calls {
					t.Errorf("batches = %d, want %d", backlog.calls, size.calls)
				}
				if backlog.due != 0 {
					t.Errorf("%d rows left, want the whole backlog worked off", backlog.due)
				}
				for i, limit := range backlog.limits {
					if limit != batchSize {
						t.Errorf("batch %d limit = %d, want %d", i+1, limit, batchSize)
					}
				}
				if len(store.calls) != 0 {
					t.Errorf("storage calls = %v, want none: the sweep is database-only", store.calls)
				}
			})
		}
	}
}

func TestRunCycle_DrainsEachSweepIndependently(t *testing.T) {
	repo := &mockRepo{}
	repo.abandonedUploads.due = 2*batchSize + 1
	repo.drainedSecrets.due = 5
	repo.expiredSecrets.due = batchSize

	w := NewWorker(time.Minute, repo, &mockFileStore{}, testMetrics())
	w.runCycle(context.Background())

	for _, c := range []struct {
		sweep      string
		calls, due int
		backlog    *sqlBacklog
	}{
		{"expired uploads", 3, 0, &repo.abandonedUploads},
		{"drained secrets", 1, 0, &repo.drainedSecrets},
		{"expired secrets", 2, 0, &repo.expiredSecrets},
	} {
		if c.backlog.calls != c.calls || c.backlog.due != c.due {
			t.Errorf("%s: %d batches, %d rows left; want %d and %d", c.sweep, c.backlog.calls, c.backlog.due, c.calls, c.due)
		}
	}
}

func TestRunCycle_AnErrorEndsADrainButKeepsItsEarlierBatches(t *testing.T) {
	for _, sweep := range batchedSweeps {
		t.Run(sweep.name, func(t *testing.T) {
			repo := &mockRepo{}
			backlog := sweep.backlog(repo)
			*backlog = sqlBacklog{due: 3 * batchSize, err: errors.New("db connection lost"), errAt: 2}
			m := testMetrics()

			w := NewWorker(time.Minute, repo, &mockFileStore{}, m)
			w.runCycle(context.Background())

			if backlog.calls != 2 {
				t.Errorf("batches = %d, want 2: the failed one ends the drain", backlog.calls)
			}
			if backlog.due != 2*batchSize {
				t.Errorf("%d rows left, want the first batch worked off before the error", backlog.due)
			}
			if got := counterValue(t, m.CleanupErrors); got != 1 {
				t.Errorf("cleanup errors = %v, want 1", got)
			}
		})
	}
}

// --- Tests: removing objects ---

func TestRunCycle_AbortsAWritingObjectsUploadsBeforeDeletingIt(t *testing.T) {
	repo := &mockRepo{doomed: []*domain.Object{
		{StorageKey: "blobs/w1", State: domain.ObjectWriting, S3UploadID: "u1"},
		// The upload id was never recorded: the upload is found by its key.
		{StorageKey: "blobs/w2", State: domain.ObjectWriting},
	}}
	store := &mockFileStore{}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, store, m)
	w.runCycle(context.Background())

	want := []string{"abort blobs/w1", "delete blobs/w1", "abort blobs/w2", "delete blobs/w2"}
	if !slices.Equal(store.calls, want) {
		t.Errorf("storage calls = %v, want %v", store.calls, want)
	}
	if len(repo.doomed) != 0 {
		t.Errorf("%d objects left, want both removed", len(repo.doomed))
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 2 {
		t.Errorf("objects deleted = %v, want 2", got)
	}
}

func TestRunCycle_OnlyDeletesAStoredObject(t *testing.T) {
	repo := &mockRepo{doomed: []*domain.Object{
		stored("blobs/s1"),
		// An upload id left on the row changes nothing: the multipart upload
		// ended when the object was assembled.
		{StorageKey: "blobs/s2", State: domain.ObjectStored, S3UploadID: "u2"},
	}}
	store := &mockFileStore{}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, store, m)
	w.runCycle(context.Background())

	want := []string{"delete blobs/s1", "delete blobs/s2"}
	if !slices.Equal(store.calls, want) {
		t.Errorf("storage calls = %v, want %v", store.calls, want)
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 2 {
		t.Errorf("objects deleted = %v, want 2", got)
	}
}

func TestRunCycle_KeepsAnObjectWhoseUploadsCannotBeAborted(t *testing.T) {
	repo := &mockRepo{doomed: []*domain.Object{writing("blobs/w"), stored("blobs/s")}}
	store := &mockFileStore{failAbort: map[string]bool{"blobs/w": true}}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, store, m)
	w.runCycle(context.Background())

	// An upload that is still open could assemble the object again after it was
	// deleted, so nothing is deleted until the abort has worked. The other
	// object of the batch is not held up.
	if want := []string{"abort blobs/w", "delete blobs/s"}; !slices.Equal(store.calls, want) {
		t.Errorf("storage calls = %v, want %v", store.calls, want)
	}
	if got := objectKeys(repo.doomed); !slices.Equal(got, []string{"blobs/w"}) {
		t.Errorf("objects left = %v, want only the one whose abort failed", got)
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 1 {
		t.Errorf("objects deleted = %v, want 1: only the removed one counts", got)
	}
	if got := counterValue(t, m.CleanupErrors); got != 1 {
		t.Errorf("cleanup errors = %v, want 1: a refused abort shows in the metrics", got)
	}

	// The next cycle tries it again, and storage is back.
	store.failAbort = nil
	store.calls = nil
	w.runCycle(context.Background())

	if want := []string{"abort blobs/w", "delete blobs/w"}; !slices.Equal(store.calls, want) {
		t.Errorf("storage calls in the next cycle = %v, want %v", store.calls, want)
	}
	if len(repo.doomed) != 0 {
		t.Errorf("%d objects left, want none", len(repo.doomed))
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 2 {
		t.Errorf("objects deleted = %v, want 2", got)
	}
}

func TestRunCycle_KeepsAnObjectWhoseDeleteFails(t *testing.T) {
	repo := &mockRepo{doomed: []*domain.Object{writing("blobs/w"), stored("blobs/s"), stored("blobs/ok")}}
	store := &mockFileStore{failDelete: map[string]bool{"blobs/w": true, "blobs/s": true}}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, store, m)
	w.runCycle(context.Background())

	want := []string{"abort blobs/w", "delete blobs/w", "delete blobs/s", "delete blobs/ok"}
	if !slices.Equal(store.calls, want) {
		t.Errorf("storage calls = %v, want %v", store.calls, want)
	}
	if got := objectKeys(repo.doomed); !slices.Equal(got, []string{"blobs/w", "blobs/s"}) {
		t.Errorf("objects left = %v, want the two whose delete failed", got)
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 1 {
		t.Errorf("objects deleted = %v, want 1: only the removed one counts", got)
	}
	if got := counterValue(t, m.CleanupErrors); got != 2 {
		t.Errorf("cleanup errors = %v, want 2: every refused delete shows in the metrics", got)
	}

	// The next cycle tries them again, and storage is back.
	store.failDelete = nil
	store.calls = nil
	w.runCycle(context.Background())

	// Aborting is repeated for the writing object; it ends nothing twice.
	if want := []string{"abort blobs/w", "delete blobs/w", "delete blobs/s"}; !slices.Equal(store.calls, want) {
		t.Errorf("storage calls in the next cycle = %v, want %v", store.calls, want)
	}
	if len(repo.doomed) != 0 {
		t.Errorf("%d objects left, want none", len(repo.doomed))
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 3 {
		t.Errorf("objects deleted = %v, want 3", got)
	}
}

func TestRunCycle_RemovesDoomedObjectsInBatchesAndCountsThem(t *testing.T) {
	for _, size := range []struct{ due, calls int }{
		{due: 0, calls: 1},
		{due: batchSize - 1, calls: 1},
		{due: batchSize, calls: 2},
		{due: 2*batchSize + 50, calls: 3},
	} {
		t.Run(fmt.Sprintf("%d due", size.due), func(t *testing.T) {
			repo := &mockRepo{doomed: storedObjects("blobs/o", size.due)}
			store := &mockFileStore{}
			m := testMetrics()

			w := NewWorker(time.Minute, repo, store, m)
			w.runCycle(context.Background())

			if repo.doomedCalls != size.calls {
				t.Errorf("batches = %d, want %d", repo.doomedCalls, size.calls)
			}
			for i, limit := range repo.doomedLimits {
				if limit != batchSize {
					t.Errorf("batch %d limit = %d, want %d", i+1, limit, batchSize)
				}
			}
			if len(repo.doomed) != 0 {
				t.Errorf("%d objects left, want the whole backlog removed", len(repo.doomed))
			}
			if len(store.calls) != size.due {
				t.Errorf("storage calls = %d, want %d: one delete each", len(store.calls), size.due)
			}
			if got := counterValue(t, m.ObjectsDeleted); got != float64(size.due) {
				t.Errorf("objects deleted = %v, want %d", got, size.due)
			}
			if got := counterValue(t, m.CleanupErrors); got != 0 {
				t.Errorf("cleanup errors = %v, want 0", got)
			}
		})
	}
}

func TestRunCycle_FailedObjectsDoNotStallTheRest(t *testing.T) {
	backlog := storedObjects("blobs/o", 2*batchSize+50)
	repo := &mockRepo{doomed: backlog}
	store := &mockFileStore{failDelete: map[string]bool{backlog[4].StorageKey: true}}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, store, m)
	w.runCycle(context.Background())

	// The failing object is tried again by every batch; everything else goes.
	if got := objectKeys(repo.doomed); !slices.Equal(got, []string{backlog[4].StorageKey}) {
		t.Errorf("objects left = %v, want only the failing one", got)
	}
	if got := counterValue(t, m.ObjectsDeleted); got != 2*batchSize+49 {
		t.Errorf("objects deleted = %v, want %d", got, 2*batchSize+49)
	}
}

func TestRunCycle_StopsWhenNoObjectCanBeRemoved(t *testing.T) {
	for _, down := range []struct {
		name    string
		objects func() []*domain.Object
		store   *mockFileStore
		calls   string // the storage call each object of the batch costs
	}{
		{
			name:    "delete fails",
			objects: func() []*domain.Object { return storedObjects("blobs/o", 2*batchSize) },
			store:   &mockFileStore{deleteErr: errors.New("storage down")},
			calls:   "delete",
		},
		{
			name: "abort fails",
			objects: func() []*domain.Object {
				objects := storedObjects("blobs/o", 2*batchSize)
				for _, object := range objects {
					object.State = domain.ObjectWriting
				}
				return objects
			},
			store: &mockFileStore{abortErr: errors.New("storage down")},
			calls: "abort",
		},
	} {
		t.Run(down.name, func(t *testing.T) {
			repo := &mockRepo{doomed: down.objects()}
			m := testMetrics()

			// A sweep that fails to stop is cut short after a few batches, so the
			// test fails instead of hanging.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			repo.afterDoomedBatch = func() {
				if repo.doomedCalls == 10 {
					cancel()
				}
			}

			w := NewWorker(time.Minute, repo, down.store, m)
			w.runCycle(ctx)

			if repo.doomedCalls != 1 {
				t.Errorf("batches = %d, want 1: retrying a failing store within the cycle is pointless", repo.doomedCalls)
			}
			// Every object of the one batch was tried, and only with the call that failed.
			attempts := 0
			for _, call := range down.store.calls {
				if strings.HasPrefix(call, down.calls+" ") {
					attempts++
				}
			}
			if attempts != batchSize || len(down.store.calls) != batchSize {
				t.Errorf("storage calls = %d, of which %d an %s; want %d, all of them", len(down.store.calls), attempts, down.calls, batchSize)
			}
			if len(repo.doomed) != 2*batchSize {
				t.Errorf("%d objects left, want all kept for the next cycle", len(repo.doomed))
			}
			if got := counterValue(t, m.ObjectsDeleted); got != 0 {
				t.Errorf("objects deleted = %v, want 0", got)
			}
		})
	}
}

func TestRunCycle_KeepsCommittedObjectBatchesAfterAnError(t *testing.T) {
	repo := &mockRepo{
		doomed:      storedObjects("blobs/o", 3*batchSize),
		doomedErr:   errors.New("db connection lost"),
		doomedErrAt: 2,
	}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, &mockFileStore{}, m)
	w.runCycle(context.Background())

	if repo.doomedCalls != 2 {
		t.Errorf("batches = %d, want 2: the failed one ends the sweep", repo.doomedCalls)
	}
	if len(repo.doomed) != 2*batchSize {
		t.Errorf("%d objects left, want the first batch removed before the error", len(repo.doomed))
	}
	if got := counterValue(t, m.ObjectsDeleted); got != batchSize {
		t.Errorf("objects deleted = %v, want %d: the first batch counts", got, batchSize)
	}
	if got := counterValue(t, m.CleanupErrors); got != 1 {
		t.Errorf("cleanup errors = %v, want 1", got)
	}
}

// --- Tests: failing steps ---

func TestRunCycle_AFailingStepDoesNotStopTheOthers(t *testing.T) {
	boom := errors.New("db connection lost")
	for _, step := range []struct {
		sweep string
		fail  func(*mockRepo)
	}{
		{"DeleteExpiredRetrievalSessions", func(r *mockRepo) { r.retrievalSessions.err = boom }},
		{"AbandonExpiredUploads", func(r *mockRepo) { r.abandonedUploads.err = boom }},
		{"DeleteFinishedUploads", func(r *mockRepo) { r.finishedUploads.err = boom }},
		{"DeleteEndedTransfers", func(r *mockRepo) { r.endedTransfers.err = boom }},
		{"DeleteDrainedSecrets", func(r *mockRepo) { r.drainedSecrets.err = boom }},
		{"DeleteExpiredSecrets", func(r *mockRepo) { r.expiredSecrets.err = boom }},
		{"DeleteExpiredPublicIDs", func(r *mockRepo) { r.expiredPublicIDs.err = boom }},
		{"DeleteDoomedObjects", func(r *mockRepo) { r.doomedErr = boom }},
	} {
		t.Run(step.sweep, func(t *testing.T) {
			repo := &mockRepo{doomed: []*domain.Object{stored("blobs/o")}}
			repo.abandonedUploads.due = 5
			repo.drainedSecrets.due = 5
			repo.expiredSecrets.due = 5
			step.fail(repo)
			m := testMetrics()

			w := NewWorker(time.Minute, repo, &mockFileStore{}, m)
			// Does not panic, and does not stop at the failure.
			w.runCycle(context.Background())

			for _, sweep := range allSweeps {
				if !slices.Contains(repo.order, sweep) {
					t.Errorf("%s did not run after %s failed; sweeps run: %v", sweep, step.sweep, repo.order)
				}
			}
			if got := counterValue(t, m.CleanupErrors); got != 1 {
				t.Errorf("cleanup errors = %v, want 1", got)
			}
		})
	}
}

func TestRunCycle_CountsEveryFailedStep(t *testing.T) {
	boom := errors.New("db connection lost")
	repo := &mockRepo{doomed: storedObjects("blobs/o", 2*batchSize), doomedErr: boom}
	repo.retrievalSessions.err = boom
	repo.abandonedUploads = sqlBacklog{due: 2 * batchSize, err: boom}
	repo.finishedUploads.err = boom
	repo.endedTransfers.err = boom
	repo.drainedSecrets = sqlBacklog{due: 2 * batchSize, err: boom}
	repo.expiredSecrets = sqlBacklog{due: 2 * batchSize, err: boom}
	repo.expiredPublicIDs = sqlBacklog{due: 2 * batchSize, err: boom}
	m := testMetrics()

	w := NewWorker(time.Minute, repo, &mockFileStore{}, m)
	w.runCycle(context.Background())

	if got := counterValue(t, m.CleanupErrors); got != float64(len(allSweeps)) {
		t.Errorf("cleanup errors = %v, want %d: one per failed step", got, len(allSweeps))
	}
	// A failing database is not hammered: each sweep gives up after one try.
	if !slices.Equal(slices.Sorted(slices.Values(repo.order)), slices.Sorted(slices.Values(allSweeps))) {
		t.Errorf("sweeps run = %v, want each of %v once", repo.order, allSweeps)
	}
}

// --- Tests: the context ---

func TestRunCycle_StopsWorkingOffABacklogOnceTheContextEnds(t *testing.T) {
	t.Run("database sweep", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		repo := &mockRepo{}
		repo.expiredSecrets = sqlBacklog{due: 3 * batchSize, afterBatch: cancel}

		w := NewWorker(time.Minute, repo, &mockFileStore{}, testMetrics())
		w.runCycle(ctx)

		if repo.expiredSecrets.calls != 1 || repo.expiredSecrets.due != 2*batchSize {
			t.Errorf("%d batches, %d rows left; want 1 batch and %d left: no batch starts once the context ended", repo.expiredSecrets.calls, repo.expiredSecrets.due, 2*batchSize)
		}
	})

	t.Run("object sweep", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		repo := &mockRepo{doomed: storedObjects("blobs/o", 3*batchSize), afterDoomedBatch: cancel}
		m := testMetrics()

		w := NewWorker(time.Minute, repo, &mockFileStore{}, m)
		w.runCycle(ctx)

		if repo.doomedCalls != 1 || len(repo.doomed) != 2*batchSize {
			t.Errorf("%d batches, %d objects left; want 1 batch and %d left: no batch starts once the context ended", repo.doomedCalls, len(repo.doomed), 2*batchSize)
		}
		if got := counterValue(t, m.ObjectsDeleted); got != batchSize {
			t.Errorf("objects deleted = %v, want %d: what was removed still counts", got, batchSize)
		}
	})
}

// tickingRepo signals every cycle it runs for, so a test can wait for cycles
// instead of sleeping.
type tickingRepo struct {
	*mockRepo
	cycles chan struct{}
}

func (r *tickingRepo) DeleteExpiredRetrievalSessions(ctx context.Context, now time.Time) (int64, error) {
	select {
	case r.cycles <- struct{}{}:
	default:
	}
	return r.mockRepo.DeleteExpiredRetrievalSessions(ctx, now)
}

// hungRepo is a database that never answers: its first sweep blocks until the
// context ends.
type hungRepo struct {
	*mockRepo
	started chan struct{}
}

func (r hungRepo) DeleteExpiredRetrievalSessions(ctx context.Context, _ time.Time) (int64, error) {
	select {
	case r.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestRun_ContextCancellation(t *testing.T) {
	repo := &tickingRepo{mockRepo: &mockRepo{}, cycles: make(chan struct{}, 1)}
	w := NewWorker(5*time.Millisecond, repo, &mockFileStore{}, testMetrics())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	// A cycle runs on every tick.
	for i := range 2 {
		select {
		case <-repo.cycles:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatalf("cycle %d did not run", i+1)
		}
	}

	cancel()
	select {
	case <-done:
		// Run returned as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}

func TestRun_ContextCancellationEndsACycleInProgress(t *testing.T) {
	repo := hungRepo{mockRepo: &mockRepo{}, started: make(chan struct{}, 1)}
	w := NewWorker(5*time.Millisecond, repo, &mockFileStore{}, testMetrics())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		w.Run(ctx)
		close(done)
	}()

	select {
	case <-repo.started:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("no cycle started")
	}

	// The cycle is stuck in a call that does not return by itself; stopping the
	// worker ends the call instead of waiting out the cycle's timeout.
	cancel()
	select {
	case <-done:
		// Run returned as expected.
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after context cancellation during a cycle")
	}
}

func keys(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%d", prefix, i)
	}
	return out
}

func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	if err := c.Write(&metric); err != nil {
		t.Fatalf("read counter: %v", err)
	}
	return metric.GetCounter().GetValue()
}
