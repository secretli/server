package domain

import (
	"testing"
	"time"
)

func TestSecretTimes(t *testing.T) {
	lifetime := 5 * time.Minute
	for _, completedAt := range []time.Time{
		time.Date(2026, 10, 9, 12, 3, 0, 0, time.UTC),
		time.Date(2026, 10, 9, 12, 3, 0, 1000, time.UTC),
		time.Date(2026, 10, 9, 12, 3, 59, 999999999, time.UTC),
		// The minute is the UTC one, whatever the zone.
		time.Date(2026, 10, 9, 17, 33, 41, 0, time.FixedZone("IST", 5*3600+30*60)),
	} {
		createdAt, expiresAt := SecretTimes(completedAt, lifetime)
		if want := time.Date(2026, 10, 9, 12, 3, 0, 0, time.UTC); !createdAt.Equal(want) {
			t.Errorf("completed at %v: created at %v, want %v", completedAt, createdAt, want)
		}
		if want := time.Date(2026, 10, 9, 12, 9, 0, 0, time.UTC); !expiresAt.Equal(want) {
			t.Errorf("completed at %v: expires at %v, want %v", completedAt, expiresAt, want)
		}
		// Never shorter than chosen, at most a minute longer.
		if left := expiresAt.Sub(completedAt); left <= lifetime || left > lifetime+time.Minute {
			t.Errorf("completed at %v: lives %v, want more than %v and at most a minute more", completedAt, left, lifetime)
		}
	}
}
