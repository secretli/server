package httpserver

import (
	"testing"
	"time"
)

const gib = 1024 * 1024 * 1024

// budgetAt is a budget whose clock the test moves.
func budgetAt(perHour int64, now *time.Time) *uploadBudget {
	b := newUploadBudget(perHour)
	b.now = func() time.Time { return *now }
	return b
}

func TestUploadBudgetAllowsItsSizeThenRefuses(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	b := budgetAt(4*gib, &now)

	for i := range 4 {
		if _, _, ok := b.reserve("198.51.100.7", gib); !ok {
			t.Fatalf("upload %d of 1 GiB refused within a 4 GiB budget", i+1)
		}
	}
	_, wait, ok := b.reserve("198.51.100.7", gib)
	if ok {
		t.Fatal("a fifth 1 GiB upload within the hour was allowed")
	}
	// 1 GiB of a 4 GiB hour comes back in a quarter of an hour.
	if wait < 14*time.Minute || wait > 16*time.Minute {
		t.Errorf("wait = %v, want about 15 minutes", wait)
	}
	if _, _, ok := b.reserve("203.0.113.9", gib); !ok {
		t.Error("another address shares the first one's budget")
	}
}

func TestUploadBudgetRefillsOverTime(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	b := budgetAt(4*gib, &now)
	if _, _, ok := b.reserve("198.51.100.7", 4*gib); !ok {
		t.Fatal("the whole budget at once was refused")
	}
	now = now.Add(14 * time.Minute)
	if _, _, ok := b.reserve("198.51.100.7", gib); ok {
		t.Error("1 GiB allowed after 14 minutes; it takes 15 to come back")
	}
	now = now.Add(2 * time.Minute)
	if _, _, ok := b.reserve("198.51.100.7", gib); !ok {
		t.Error("1 GiB refused after 16 minutes")
	}
}

func TestUploadBudgetReleaseGivesTheBytesBack(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	b := budgetAt(4*gib, &now)
	release, _, ok := b.reserve("198.51.100.7", 4*gib)
	if !ok {
		t.Fatal("the whole budget at once was refused")
	}
	release()
	if _, _, ok := b.reserve("198.51.100.7", 4*gib); !ok {
		t.Error("the budget a failed start gave back is not there")
	}
}

func TestUploadBudgetRefusesMoreThanItEverHolds(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	b := budgetAt(gib, &now)
	if _, _, ok := b.reserve("198.51.100.7", gib+1); ok {
		t.Error("more than the whole budget was allowed")
	}
}

func TestUploadBudgetForgetsAddressesWhoseBucketIsFull(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	b := budgetAt(4*gib, &now)
	b.reserve("198.51.100.7", gib)
	b.reserve("203.0.113.9", 4*gib)

	// Half an hour later the first bucket is full again, the second isn't.
	now = now.Add(30 * time.Minute)
	b.reserve("192.0.2.1", 1)
	b.mu.Lock()
	_, first := b.buckets["198.51.100.7"]
	_, second := b.buckets["203.0.113.9"]
	b.mu.Unlock()
	if first {
		t.Error("an address whose budget is full again is still remembered")
	}
	if !second {
		t.Error("an address still using its budget was forgotten")
	}
}

func TestUploadBudgetNilAllowsEverything(t *testing.T) {
	var b *uploadBudget
	if b != newUploadBudget(0) {
		t.Fatal("a budget of 0 is not off")
	}
	release, _, ok := b.reserve("198.51.100.7", 100*gib)
	if !ok {
		t.Fatal("no budget refused an upload")
	}
	release()
}

func TestRetryAfterSeconds(t *testing.T) {
	for wait, want := range map[time.Duration]int{0: 1, time.Millisecond: 1, time.Second: 1, 1500 * time.Millisecond: 2, 15 * time.Minute: 900} {
		if got := retryAfterSeconds(wait); got != want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", wait, got, want)
		}
	}
}
