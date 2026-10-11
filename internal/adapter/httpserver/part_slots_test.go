package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
)

func TestPartSlotsBoundTheInstanceAndEachClient(t *testing.T) {
	slots := newPartSlots(3, 2, 50*time.Millisecond)
	take := func(client string) (func(), *httptest.ResponseRecorder) {
		rec := httptest.NewRecorder()
		c := echo.New().NewContext(httptest.NewRequest(http.MethodPut, "/", nil), rec)
		release, ok := slots.acquire(c, client)
		if !ok {
			return nil, rec
		}
		return release, rec
	}

	a1, _ := take("198.51.100.7")
	a2, _ := take("198.51.100.7")
	if a1 == nil || a2 == nil {
		t.Fatal("a client's first two parts were refused")
	}
	if release, rec := take("198.51.100.7"); release != nil || rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("a client's third part: %d, Retry-After %q; want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}

	b1, _ := take("203.0.113.9")
	if b1 == nil {
		t.Fatal("another client's part was refused while the instance had a slot")
	}
	started := time.Now()
	if release, rec := take("192.0.2.1"); release != nil || rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("with every slot taken: %d, Retry-After %q; want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	if waited := time.Since(started); waited < 50*time.Millisecond {
		t.Errorf("turned away after %v, before waiting for a slot", waited)
	}

	a1()
	c1, _ := take("192.0.2.1")
	if c1 == nil {
		t.Fatal("a slot given back was not taken")
	}
	a3, _ := take("198.51.100.7")
	if a3 != nil {
		t.Error("a client got a slot back that the instance doesn't have free")
	}
	for _, release := range []func(){a2, b1, c1} {
		release()
	}
	slots.mu.Lock()
	defer slots.mu.Unlock()
	if len(slots.taken) != 0 || len(slots.all) != 0 {
		t.Errorf("after every release: %v per client, %d in all", slots.taken, len(slots.all))
	}
}
