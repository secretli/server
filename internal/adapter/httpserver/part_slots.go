package httpserver

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
)

const (
	// partSlotsPerInstance is how many part bodies one instance spools at
	// once. Each is up to 32 MiB in a temporary file, and arrives as slowly
	// as its sender sends it; without a bound, many slow parts would pin
	// goroutines, file descriptors and disk. Clients send three at a time.
	partSlotsPerInstance = 24
	// partSlotsPerClient keeps one client from taking every slot: two
	// uploads at once each.
	partSlotsPerClient = 6
	// partSlotWait is how long a part waits for a slot of the instance
	// before it is turned away; honest bursts pass within it.
	partSlotWait = 5 * time.Second
	// partBodyTimeout is how long a part's body may take to arrive: 32 MiB
	// at about 40 KB/s. The server's read timeout of 30 minutes is for every
	// request; a part that trickles holds a slot, so it gets less.
	partBodyTimeout = 15 * time.Minute
)

// partSlots bounds the part bodies being spooled, on the whole instance and
// per client. Both clients retry 429 and 503 after Retry-After.
type partSlots struct {
	all       chan struct{}
	perClient int
	wait      time.Duration

	mu    sync.Mutex
	taken map[string]int
}

func newPartSlots(total, perClient int, wait time.Duration) *partSlots {
	return &partSlots{all: make(chan struct{}, total), perClient: perClient, wait: wait, taken: map[string]int{}}
}

// acquire takes a slot for client, waiting up to s.wait for one of the
// instance's. It returns the function that gives the slot back, or, when
// there is none, writes the refusal and returns false.
func (s *partSlots) acquire(c *echo.Context, client string) (release func(), ok bool) {
	s.mu.Lock()
	if s.taken[client] >= s.perClient {
		s.mu.Unlock()
		c.Response().Header().Set("Retry-After", strconv.Itoa(5))
		_ = c.JSON(http.StatusTooManyRequests, map[string]string{"error": "too many parts at once from this address; try again shortly"})
		return nil, false
	}
	s.taken[client]++
	s.mu.Unlock()
	giveBackClient := func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.taken[client]--; s.taken[client] <= 0 {
			delete(s.taken, client)
		}
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), s.wait)
	defer cancel()
	select {
	case s.all <- struct{}{}:
		return func() {
			<-s.all
			giveBackClient()
		}, true
	case <-ctx.Done():
		giveBackClient()
		c.Response().Header().Set("Retry-After", strconv.Itoa(5))
		_ = c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "the server is busy with other uploads; try again shortly"})
		return nil, false
	}
}
