package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secretli/server/internal/domain"
)

// statsTimeout bounds the query a scrape runs, so a slow database costs a
// scrape these gauges, not the whole scrape.
const statsTimeout = 2 * time.Second

// The kinds of secret secrets_live tells apart.
const (
	kindOneTime  = "one_time"
	kindReusable = "reusable"
)

// StatsCollector reports how secrets, storage and the cleanup stand, read
// from the database when Prometheus scrapes. Every replica reads the same
// totals, so the gauges agree whichever one is asked. They are totals of the
// current state only: no secret is told apart, and nothing is stored for
// them.
//
// Deliberately not reported: uploads or downloads under way, closing
// secrets and open short-code transfers. Each counts something that lasts
// only while one person acts, so at scrape granularity, kept in a
// third-party store, it would record when someone uploaded, downloaded or
// handed over a secret, and for how long. Do not add them.
type StatsCollector struct {
	stats func(ctx context.Context) (domain.MetricsStats, error)
	limit int64

	liveSecrets          *prometheus.Desc
	storedBytes          *prometheus.Desc
	overdueSecrets       *prometheus.Desc
	doomedObjects        *prometheus.Desc
	removalFailedObjects *prometheus.Desc
	stuckUploads         *prometheus.Desc
	reservedPublicIDs    *prometheus.Desc
	storedLimit          *prometheus.Desc
}

// NewStatsCollector reads the totals through stats on every scrape. limit is
// the storage cap in bytes, reported alongside so a dashboard can draw it;
// 0 (no cap) is not reported.
func NewStatsCollector(stats func(ctx context.Context) (domain.MetricsStats, error), limit int64) *StatsCollector {
	return &StatsCollector{
		stats: stats,
		limit: limit,
		liveSecrets: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "secrets_live"),
			"Secrets that can be opened now, by kind: one_time or reusable.", []string{"kind"}, nil),
		storedBytes: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "stored_bytes"),
			"Bytes the secrets holding an object take up in storage, uploads under way included.", nil, nil),
		overdueSecrets: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "secrets_overdue"),
			"Secrets past their expiry that the cleanup has not forgotten yet; normally 0, and above it for long only while the cleanup is stuck.", nil, nil),
		doomedObjects: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "objects_doomed"),
			"Objects waiting for the cleanup to delete them from storage; normally near 0.", nil, nil),
		removalFailedObjects: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "objects_removal_failed"),
			"Doomed objects that storage has refused to delete at least once; normally 0.", nil, nil),
		stuckUploads: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "uploads_stuck"),
			"Uploads still under way past their own expiry, which the cleanup should have abandoned; normally 0.", nil, nil),
		reservedPublicIDs: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "public_ids_reserved"),
			"Links of secrets that are gone, kept reserved until their expiry so that nobody can put other content under them.", nil, nil),
		storedLimit: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "stored_bytes_limit"),
			"The cap on stored bytes, past which new uploads are refused.", nil, nil),
	}
}

func (c *StatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.liveSecrets
	ch <- c.storedBytes
	ch <- c.overdueSecrets
	ch <- c.doomedObjects
	ch <- c.removalFailedObjects
	ch <- c.stuckUploads
	ch <- c.reservedPublicIDs
	ch <- c.storedLimit
}

func (c *StatsCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), statsTimeout)
	defer cancel()
	stats, err := c.stats(ctx)
	if err != nil {
		// Leave the gauges out of this scrape rather than fail it.
		slog.Warn("metrics: totals unavailable", "error", err)
		return
	}
	gauge := func(desc *prometheus.Desc, value int64, labels ...string) {
		ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(value), labels...)
	}
	// Both kinds every time, 0 included, so that their sum is the total.
	gauge(c.liveSecrets, stats.LiveOneTime, kindOneTime)
	gauge(c.liveSecrets, stats.LiveReusable, kindReusable)
	gauge(c.storedBytes, stats.StoredBytes)
	gauge(c.overdueSecrets, stats.OverdueSecrets)
	gauge(c.doomedObjects, stats.DoomedObjects)
	gauge(c.removalFailedObjects, stats.RemovalFailedObjects)
	gauge(c.stuckUploads, stats.StuckUploads)
	gauge(c.reservedPublicIDs, stats.ReservedPublicIDs)
	if c.limit > 0 {
		gauge(c.storedLimit, c.limit)
	}
}
