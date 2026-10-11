package apitest

import (
	"net/http"
	"sync"
	"testing"
)

// TestAOneTimeSecretOpenedByManyAtOnceIsOpenedOnce is the standing race
// check of promise P3: many simultaneous openings of a one-time secret, and
// exactly one of them wins. The others must see what anyone sees afterwards:
// a secret that is gone, the same 404 as one that never was. Runs against a
// server with RATE_LIMIT_MULTIPLIER raised, like the other tests here.
func TestAOneTimeSecretOpenedByManyAtOnceIsOpenedOnce(t *testing.T) {
	const attempts = 40

	a := server(t)
	s := newSecret(t, 4096, true)
	a.upload(s)

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan int, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r := a.startRetrieval(s, s.blobToken, "")
			results <- r.status
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	counts := make(map[int]int)
	for status := range results {
		counts[status]++
	}
	if counts[http.StatusCreated] != 1 {
		t.Errorf("%d of %d simultaneous openings succeeded, want exactly 1 (all: %v)",
			counts[http.StatusCreated], attempts, counts)
	}
	for status := range counts {
		if status != http.StatusCreated && status != http.StatusNotFound {
			t.Errorf("a losing opening got %d, want 404 (all: %v)", status, counts)
		}
	}
}
