package metrics

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/secretli/server/internal/domain"
)

// gathered is what a scrape of a registry returns: every gauge's value by
// series, written name{label="value",...}, and every family's help by name.
type gathered struct {
	values map[string]float64
	help   map[string]string
}

func gather(t *testing.T, reg *prometheus.Registry) gathered {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	g := gathered{values: map[string]float64{}, help: map[string]string{}}
	for _, family := range families {
		g.help[family.GetName()] = family.GetHelp()
		for _, metric := range family.GetMetric() {
			var labels []string
			for _, label := range metric.GetLabel() {
				labels = append(labels, label.GetName()+`="`+label.GetValue()+`"`)
			}
			series := family.GetName()
			if len(labels) > 0 {
				series += "{" + strings.Join(labels, ",") + "}"
			}
			g.values[series] = metric.GetGauge().GetValue()
		}
	}
	return g
}

func statsCollector(stats domain.MetricsStats, err error, limit int64) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(NewStatsCollector(func(context.Context) (domain.MetricsStats, error) {
		return stats, err
	}, limit))
	return reg
}

func TestStatsCollectorReportsTheTotals(t *testing.T) {
	got := gather(t, statsCollector(domain.MetricsStats{
		LiveOneTime:          3,
		LiveReusable:         5,
		StoredBytes:          4096,
		OverdueSecrets:       2,
		DoomedObjects:        7,
		RemovalFailedObjects: 1,
		StuckUploads:         4,
		ReservedPublicIDs:    6,
	}, nil, 1<<30))

	want := map[string]float64{
		`secretli_secrets_live{kind="one_time"}`: 3,
		`secretli_secrets_live{kind="reusable"}`: 5,
		"secretli_stored_bytes":                  4096,
		"secretli_secrets_overdue":               2,
		"secretli_objects_doomed":                7,
		"secretli_objects_removal_failed":        1,
		"secretli_uploads_stuck":                 4,
		"secretli_public_ids_reserved":           6,
		"secretli_stored_bytes_limit":            1 << 30,
	}
	if !maps.Equal(got.values, want) {
		t.Errorf("series = %v, want %v", got.values, want)
	}

	wantHelp := map[string]string{
		"secretli_secrets_live":           "Secrets that can be opened now, by kind: one_time or reusable.",
		"secretli_stored_bytes":           "Bytes the secrets holding an object take up in storage, uploads under way included.",
		"secretli_secrets_overdue":        "Secrets past their expiry that the cleanup has not forgotten yet; normally 0, and above it for long only while the cleanup is stuck.",
		"secretli_objects_doomed":         "Objects waiting for the cleanup to delete them from storage; normally near 0.",
		"secretli_objects_removal_failed": "Doomed objects that storage has refused to delete at least once; normally 0.",
		"secretli_uploads_stuck":          "Uploads still under way past their own expiry, which the cleanup should have abandoned; normally 0.",
		"secretli_public_ids_reserved":    "Links of secrets that are gone, kept reserved until their expiry so that nobody can put other content under them.",
		"secretli_stored_bytes_limit":     "The cap on stored bytes, past which new uploads are refused.",
	}
	if !maps.Equal(got.help, wantHelp) {
		t.Errorf("help = %v, want %v", got.help, wantHelp)
	}
}

func TestStatsCollectorReportsBothKindsOfLiveSecretsWhenThereAreNone(t *testing.T) {
	got := gather(t, statsCollector(domain.MetricsStats{}, nil, 1<<30))

	// sum(secretli_secrets_live) is the total, so neither kind may be missing.
	for _, series := range []string{`secretli_secrets_live{kind="one_time"}`, `secretli_secrets_live{kind="reusable"}`} {
		value, ok := got.values[series]
		if !ok || value != 0 {
			t.Errorf("%s = %v (reported: %v), want 0", series, value, ok)
		}
	}
}

func TestStatsCollectorLeavesOutTheLimitWithoutACap(t *testing.T) {
	got := gather(t, statsCollector(domain.MetricsStats{}, nil, 0))

	if _, ok := got.values["secretli_stored_bytes_limit"]; ok {
		t.Error("the limit is reported although there is no cap")
	}
	if names := slices.Sorted(maps.Keys(got.help)); len(names) != 7 {
		t.Errorf("families = %v, want the other seven", names)
	}
}

func TestStatsCollectorSkipsItsGaugesWhenTheDatabaseFails(t *testing.T) {
	got := gather(t, statsCollector(domain.MetricsStats{}, errors.New("database down"), 1<<30))

	// The scrape still succeeds; only these gauges are missing from it.
	if len(got.values) != 0 {
		t.Errorf("gauges = %v, want none while the totals cannot be read", got.values)
	}
}
