package cleanup

import (
	"context"
	"log/slog"
	"time"

	"github.com/secretli/server/internal/adapter/metrics"
	"github.com/secretli/server/internal/domain"
)

const (
	// cycleTimeout bounds one cleanup pass, so a hung storage call cannot
	// stall the cleanup for good. Only the object sweep talks to storage, and
	// it locks only rows that no request touches.
	cycleTimeout = 10 * time.Minute
	// finishedUploadRetention is how long a completed or abandoned upload is
	// kept, so a client retrying complete or abort still gets a consistent
	// answer. Clients retry within seconds, so a few minutes do; anything
	// longer only keeps the upload's traces around.
	finishedUploadRetention = 10 * time.Minute
	// endedTransferRetention keeps an ended transfer briefly, so the other
	// side's next poll learns why it ended instead of finding nothing.
	endedTransferRetention = time.Minute
	// batchSize bounds how many rows one cleanup transaction locks. Each batch
	// commits, so a large backlog (after an outage, say) is worked off across
	// batches and cycles instead of in one transaction that times out and
	// rolls back every time.
	batchSize = 100
)

// Repo is the slice of the datastore this worker touches.
type Repo interface {
	DeleteExpiredRetrievalSessions(ctx context.Context, now time.Time) (int64, error)
	AbandonExpiredUploads(ctx context.Context, now time.Time, limit int) (int, error)
	DeleteFinishedUploads(ctx context.Context, finishedBefore time.Time) (int64, error)
	DeleteDrainedSecrets(ctx context.Context, now time.Time, limit int) (int, error)
	DeleteExpiredSecrets(ctx context.Context, now time.Time, limit int) (int, error)
	DeleteExpiredPublicIDs(ctx context.Context, now time.Time, limit int) (int, error)
	DeleteDoomedObjects(ctx context.Context, limit int, remove func(object *domain.Object) error) (domain.CleanupBatch, error)
	DeleteEndedTransfers(ctx context.Context, endedBefore time.Time) (int64, error)
}

type Worker struct {
	interval  time.Duration
	repo      Repo
	fileStore domain.MultipartFileStore
	metrics   *metrics.SecretMetrics
}

func NewWorker(interval time.Duration, repo Repo, fileStore domain.MultipartFileStore, m *metrics.SecretMetrics) *Worker {
	return &Worker{
		interval:  interval,
		repo:      repo,
		fileStore: fileStore,
		metrics:   m,
	}
}

func (w *Worker) Run(ctx context.Context) {
	slog.InfoContext(ctx, "cleanup worker started", "interval", w.interval)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.InfoContext(ctx, "cleanup worker stopped")
			return
		case <-ticker.C:
			w.runCycle(ctx)
		}
	}
}

// runCycle ends what ran out and dooms the objects nothing may read any more,
// all in the database, and then removes the doomed objects from storage. The
// object sweep runs last, so what this cycle doomed is usually gone by its
// end.
func (w *Worker) runCycle(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, cycleTimeout)
	defer cancel()
	now := time.Now()

	w.sweep(ctx, "expired retrieval sessions", func() (int64, error) {
		return w.repo.DeleteExpiredRetrievalSessions(ctx, now)
	})
	w.sweep(ctx, "expired uploads", func() (int64, error) {
		return drainSQL(ctx, func() (int, error) { return w.repo.AbandonExpiredUploads(ctx, now, batchSize) })
	})
	w.sweep(ctx, "finished uploads", func() (int64, error) {
		return w.repo.DeleteFinishedUploads(ctx, now.Add(-finishedUploadRetention))
	})
	w.sweep(ctx, "ended transfers", func() (int64, error) {
		return w.repo.DeleteEndedTransfers(ctx, now.Add(-endedTransferRetention))
	})
	w.sweep(ctx, "drained one-time secrets", func() (int64, error) {
		return drainSQL(ctx, func() (int, error) { return w.repo.DeleteDrainedSecrets(ctx, now, batchSize) })
	})
	w.sweep(ctx, "expired secrets", func() (int64, error) {
		return drainSQL(ctx, func() (int, error) { return w.repo.DeleteExpiredSecrets(ctx, now, batchSize) })
	})
	// After the secrets: a secret's id is freed in the cycle that forgets it,
	// and a gone secret's id once its expiry has passed.
	w.sweep(ctx, "expired public ids", func() (int64, error) {
		return drainSQL(ctx, func() (int, error) { return w.repo.DeleteExpiredPublicIDs(ctx, now, batchSize) })
	})

	removed, err := drainBatches(ctx, func() (domain.CleanupBatch, error) {
		return w.repo.DeleteDoomedObjects(ctx, batchSize, func(object *domain.Object) error {
			// The object stays doomed and is tried again next cycle. Count it,
			// so storage refusing deletes shows in the metrics, not only in
			// the log.
			err := w.removeObject(ctx, object)
			if err != nil {
				w.metrics.CleanupErrors.Inc()
			}
			return err
		})
	})
	if removed > 0 {
		slog.InfoContext(ctx, "cleanup: deleted objects", "count", removed)
		w.metrics.ObjectsDeleted.Add(float64(removed))
	}
	if err != nil {
		slog.ErrorContext(ctx, "cleanup: object cleanup failed", "error", err)
		w.metrics.CleanupErrors.Inc()
	}
}

// removeObject deletes an object from storage. One that was still being
// written may have a multipart upload open, holding uploaded parts; those are
// aborted first. The object itself is deleted either way: a crash between
// assembling an upload and recording it leaves an object behind a row that
// still says writing.
func (w *Worker) removeObject(ctx context.Context, object *domain.Object) error {
	if object.State == domain.ObjectWriting {
		if err := w.fileStore.AbortMultipartUploads(ctx, object.StorageKey); err != nil {
			return err
		}
	}
	return w.fileStore.Delete(ctx, object.StorageKey)
}

// sweep runs one database-only cleanup step and logs its outcome. A failed
// step does not stop the others; a cycle cut short (at shutdown, say) skips
// the steps it has no time for.
func (w *Worker) sweep(ctx context.Context, what string, step func() (int64, error)) {
	if ctx.Err() != nil {
		return
	}
	count, err := step()
	if count > 0 {
		slog.InfoContext(ctx, "cleanup: "+what, "count", count)
	}
	if err != nil {
		slog.ErrorContext(ctx, "cleanup: "+what+" failed", "error", err)
		w.metrics.CleanupErrors.Inc()
	}
}

// drainSQL runs a database-only batch until a short batch says the backlog
// is worked off, and returns how many rows it handled.
func drainSQL(ctx context.Context, batch func() (int, error)) (int64, error) {
	var handled int64
	for ctx.Err() == nil {
		n, err := batch()
		handled += int64(n)
		if err != nil {
			return handled, err
		}
		if n < batchSize {
			break
		}
	}
	return handled, nil
}

// drainBatches runs batch until the backlog is worked off and returns how
// many rows were removed. It stops at a short batch (nothing left), at a
// batch that removed nothing (every row failed, e.g. storage is down; the
// next cycle retries) or at an error, whose earlier batches stay committed.
// Objects that fail count one more failed removal and sink behind the rest,
// so even a full batch of objects that storage keeps refusing cannot stall
// the others. Every batch either removes a row or ends the loop, so it
// ends.
func drainBatches(ctx context.Context, batch func() (domain.CleanupBatch, error)) (int, error) {
	removed := 0
	for ctx.Err() == nil {
		result, err := batch()
		removed += result.Removed
		if err != nil {
			return removed, err
		}
		if result.Found < batchSize || result.Removed == 0 {
			break
		}
	}
	return removed, nil
}
