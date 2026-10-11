package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
)

func TestLiveness(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/live", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := Liveness(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want %q", resp.Status, "ok")
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json; charset=UTF-8" && ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

type mockPinger struct {
	err error
}

func (m *mockPinger) Ping(_ context.Context) error {
	return m.err
}

func TestReadinessWithDB_Healthy(t *testing.T) {
	e := echo.New()
	handler := ReadinessWithDB(&mockPinger{err: nil})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want %q", resp.Status, "ok")
	}
}

func TestReadinessWithDB_Unhealthy(t *testing.T) {
	e := echo.New()
	handler := ReadinessWithDB(&mockPinger{err: errors.New("connection refused")})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := handler(c); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}

	var resp healthResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.Status != "unavailable" {
		t.Errorf("status = %q, want %q", resp.Status, "unavailable")
	}
}

type countingPinger struct {
	pings int
	err   error
}

func (p *countingPinger) Ping(context.Context) error {
	p.pings++
	return p.err
}

// A ping that succeeded answers the checks within readyFor; a failed one
// answers none, so the next check pings again.
func TestReadinessReusesAFreshPing(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	check := func(handler echo.HandlerFunc) int {
		t.Helper()
		rec := httptest.NewRecorder()
		if err := handler(echo.New().NewContext(httptest.NewRequest(http.MethodGet, "/api/v1/health/ready", nil), rec)); err != nil {
			t.Fatal(err)
		}
		return rec.Code
	}

	pinger := &countingPinger{}
	handler := readiness(pinger, time.Second, func() time.Time { return now })
	for range 100 {
		if code := check(handler); code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
	}
	if pinger.pings != 1 {
		t.Errorf("%d pings for 100 checks within a second, want 1", pinger.pings)
	}
	now = now.Add(time.Second)
	check(handler)
	if pinger.pings != 2 {
		t.Errorf("%d pings after the result went stale, want 2", pinger.pings)
	}

	failing := &countingPinger{err: errors.New("connection refused")}
	handler = readiness(failing, time.Second, func() time.Time { return now })
	for range 3 {
		if code := check(handler); code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503", code)
		}
	}
	if failing.pings != 3 {
		t.Errorf("%d pings for 3 checks against a failing database, want 3", failing.pings)
	}
}
