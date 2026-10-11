package httpserver

import (
	"math"
	"sync"
	"time"
)

// uploadBudgetSweepEvery is how often addresses whose budget is full again
// are forgotten.
const uploadBudgetSweepEvery = 10 * time.Minute

// uploadBudget limits how many bytes one client address may declare for new
// uploads. A secret's declared size counts against the storage cap from the
// start of its upload, before anything arrives, so without it a few addresses
// could reserve the whole cap with uploads that never send a byte.
//
// Each address has a bucket that holds perHour bytes and refills at perHour
// an hour. Starting an upload takes its declared size; a start that fails
// gives it back. Like the rate limits, it lives in memory only and per server
// instance, and an address whose bucket is full again is forgotten: nothing
// about it is kept that the next request wouldn't rebuild.
type uploadBudget struct {
	perHour int64
	now     func() time.Time

	mu        sync.Mutex
	buckets   map[string]*budgetBucket
	lastSweep time.Time
}

// budgetBucket is the bytes an address has left, as of last.
type budgetBucket struct {
	left float64
	last time.Time
}

// newUploadBudget returns a budget of perHour bytes an hour per address, or
// nil, which allows everything, when perHour is 0 or less.
func newUploadBudget(perHour int64) *uploadBudget {
	if perHour <= 0 {
		return nil
	}
	return &uploadBudget{perHour: perHour, now: time.Now, buckets: map[string]*budgetBucket{}}
}

// reserve takes n bytes from the address's budget. When it allows them, it
// returns a function that gives them back. When it refuses, it returns how
// long until n bytes would be there.
func (b *uploadBudget) reserve(address string, n int64) (release func(), wait time.Duration, ok bool) {
	if b == nil {
		return func() {}, 0, true
	}
	if n > b.perHour {
		// More than the bucket ever holds: no wait would help.
		return nil, time.Hour, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	b.sweep(now)
	bucket, found := b.buckets[address]
	if !found {
		bucket = &budgetBucket{left: float64(b.perHour), last: now}
		b.buckets[address] = bucket
	}
	b.refill(bucket, now)
	if bucket.left < float64(n) {
		return nil, b.timeFor(float64(n) - bucket.left), false
	}
	bucket.left -= float64(n)
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.refill(bucket, b.now())
		bucket.left = min(float64(b.perHour), bucket.left+float64(n))
	}, 0, true
}

// refill adds what came back since the bucket was last looked at.
func (b *uploadBudget) refill(bucket *budgetBucket, now time.Time) {
	if elapsed := now.Sub(bucket.last); elapsed > 0 {
		bucket.left = min(float64(b.perHour), bucket.left+float64(b.perHour)*elapsed.Hours())
		bucket.last = now
	}
}

// timeFor is how long it takes the budget to give back bytes.
func (b *uploadBudget) timeFor(bytes float64) time.Duration {
	return time.Duration(bytes / float64(b.perHour) * float64(time.Hour))
}

// sweep forgets the addresses whose bucket is full again.
func (b *uploadBudget) sweep(now time.Time) {
	if now.Sub(b.lastSweep) < uploadBudgetSweepEvery {
		return
	}
	for address, bucket := range b.buckets {
		b.refill(bucket, now)
		if bucket.left >= float64(b.perHour) {
			delete(b.buckets, address)
		}
	}
	b.lastSweep = now
}

// retryAfterSeconds is a wait as a Retry-After value: whole seconds, rounded
// up, at least 1.
func retryAfterSeconds(wait time.Duration) int {
	return max(1, int(math.Ceil(wait.Seconds())))
}
