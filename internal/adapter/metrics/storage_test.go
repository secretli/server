package metrics

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secretli/server/internal/domain"
)

// gauges gathers reg and returns every gauge's value by name.
func gauges(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	values := map[string]float64{}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			values[family.GetName()] = metric.GetGauge().GetValue()
		}
	}
	return values
}

func TestStorageCollectorReportsTheTotals(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStorageCollector(func(context.Context) (domain.StorageStats, error) {
		return domain.StorageStats{LiveSecrets: 3, StoredBytes: 4096, DoomedObjects: 1}, nil
	}, 1<<30))

	got := gauges(t, reg)
	want := map[string]float64{
		"secretli_secrets_live":       3,
		"secretli_stored_bytes":       4096,
		"secretli_objects_doomed":     1,
		"secretli_stored_bytes_limit": 1 << 30,
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %v, want %v", name, got[name], value)
		}
	}
}

func TestStorageCollectorLeavesOutTheLimitWithoutACap(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStorageCollector(func(context.Context) (domain.StorageStats, error) {
		return domain.StorageStats{}, nil
	}, 0))

	if _, ok := gauges(t, reg)["secretli_stored_bytes_limit"]; ok {
		t.Error("the limit is reported although there is no cap")
	}
}

func TestStorageCollectorSkipsItsGaugesWhenTheDatabaseFails(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStorageCollector(func(context.Context) (domain.StorageStats, error) {
		return domain.StorageStats{}, errors.New("database down")
	}, 1<<30))

	// The scrape still succeeds; only these gauges are missing from it.
	if got := gauges(t, reg); len(got) != 0 {
		t.Errorf("gauges = %v, want none while the totals cannot be read", got)
	}
}
