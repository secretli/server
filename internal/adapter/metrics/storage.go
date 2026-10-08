package metrics

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secretli/server/internal/domain"
)

// storageStatsTimeout bounds the query a scrape runs, so a slow database
// costs a scrape these gauges, not the whole scrape.
const storageStatsTimeout = 2 * time.Second

// StorageCollector reports what storage holds, read from the database when
// Prometheus scrapes. Every replica reads the same totals, so the gauges agree
// whichever one is asked. They are totals only: no secret is told apart.
type StorageCollector struct {
	stats func(ctx context.Context) (domain.StorageStats, error)
	limit int64

	liveSecrets   *prometheus.Desc
	storedBytes   *prometheus.Desc
	doomedObjects *prometheus.Desc
	storedLimit   *prometheus.Desc
}

// NewStorageCollector reads the totals through stats on every scrape. limit
// is the storage cap in bytes, reported alongside so a dashboard can draw it;
// 0 (no cap) is not reported.
func NewStorageCollector(stats func(ctx context.Context) (domain.StorageStats, error), limit int64) *StorageCollector {
	return &StorageCollector{
		stats: stats,
		limit: limit,
		liveSecrets: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "secrets_live"),
			"Secrets that can be opened now.", nil, nil),
		storedBytes: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "stored_bytes"),
			"Bytes the secrets holding an object take up in storage, uploads under way included.", nil, nil),
		doomedObjects: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "objects_doomed"),
			"Objects waiting for the cleanup to delete them from storage; normally near 0.", nil, nil),
		storedLimit: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "stored_bytes_limit"),
			"The cap on stored bytes, past which new uploads are refused.", nil, nil),
	}
}

func (c *StorageCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.liveSecrets
	ch <- c.storedBytes
	ch <- c.doomedObjects
	ch <- c.storedLimit
}

func (c *StorageCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), storageStatsTimeout)
	defer cancel()
	stats, err := c.stats(ctx)
	if err != nil {
		// Leave the gauges out of this scrape rather than fail it.
		slog.Warn("metrics: storage totals unavailable", "error", err)
		return
	}
	ch <- prometheus.MustNewConstMetric(c.liveSecrets, prometheus.GaugeValue, float64(stats.LiveSecrets))
	ch <- prometheus.MustNewConstMetric(c.storedBytes, prometheus.GaugeValue, float64(stats.StoredBytes))
	ch <- prometheus.MustNewConstMetric(c.doomedObjects, prometheus.GaugeValue, float64(stats.DoomedObjects))
	if c.limit > 0 {
		ch <- prometheus.MustNewConstMetric(c.storedLimit, prometheus.GaugeValue, float64(c.limit))
	}
}
