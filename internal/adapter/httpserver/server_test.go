package httpserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/secretli/server/internal/platform/config"
)

// fullMockRepo satisfies domain.Repo so the complete route table, including
// multipart uploads and transfers, is registered. The secret and upload mocks
// keep separate rows: these tests drive uploads, not reads of their secrets.
type fullMockRepo struct {
	*mockSecretRepo
	*uploadMockRepo
	*transferMockRepo
}

func newTestApp(t *testing.T, cfg config.Config) *App {
	t.Helper()
	repo := fullMockRepo{mockSecretRepo: newMockRepo(), uploadMockRepo: newUploadMockRepo(), transferMockRepo: newTransferMockRepo()}
	app, err := New(cfg, "test", nil, repo, newUploadMockStore(), nil, prometheus.NewRegistry())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return app
}

func createSessionBody(t *testing.T, label string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"public_id":       testPublicID(label),
		"metadata_token":  testToken(label + " metadata"),
		"blob_token":      testToken(label + " blob"),
		"deletion_token":  testToken(label + " deletion"),
		"encrypted_meta":  testEncryptedMeta(),
		"expiration":      "1d",
		"burn_after_read": false,
		"blob_size":       1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestApp_RejectsInvalidTrustedProxies(t *testing.T) {
	repo := fullMockRepo{mockSecretRepo: newMockRepo(), uploadMockRepo: newUploadMockRepo(), transferMockRepo: newTransferMockRepo()}
	if _, err := New(config.Config{TrustedProxies: "nope"}, "test", nil, repo, newUploadMockStore(), nil, prometheus.NewRegistry()); err == nil {
		t.Fatal("expected error for invalid TRUSTED_PROXIES")
	}
}

func TestApp_SpoofedForwardedForDoesNotBypassRateLimit(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20})

	// The upload-session create route allows 10 requests per minute per client.
	var statuses []int
	for i := 0; i < 12; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(createSessionBody(t, fmt.Sprintf("spoof-%d", i))))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.RemoteAddr = "203.0.113.7:4321"
		// Rotate the forwarded header on every request as an attacker would.
		req.Header.Set(echo.HeaderXForwardedFor, fmt.Sprintf("198.51.100.%d", i+1))
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		statuses = append(statuses, rec.Code)
	}

	for i, code := range statuses[:10] {
		if code != http.StatusCreated {
			t.Fatalf("request %d: status = %d, want %d", i, code, http.StatusCreated)
		}
	}
	for i, code := range statuses[10:] {
		if code != http.StatusTooManyRequests {
			t.Fatalf("request %d: status = %d, want %d (rate limit bypassed via X-Forwarded-For)", i+10, code, http.StatusTooManyRequests)
		}
	}
}

func TestApp_RateLimitMultiplierRaisesTheLimits(t *testing.T) {
	createSessions := func(app *App, client string, n int) (created, limited int) {
		for i := 0; i < n; i++ {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(createSessionBody(t, fmt.Sprintf("%s-%d", client, i))))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			req.RemoteAddr = client + ":4321"
			rec := httptest.NewRecorder()
			app.echo.ServeHTTP(rec, req)
			switch rec.Code {
			case http.StatusCreated:
				created++
			case http.StatusTooManyRequests:
				limited++
			default:
				t.Fatalf("status = %d", rec.Code)
			}
		}
		return created, limited
	}

	// The real limit: 10 new secrets a minute.
	if created, limited := createSessions(newTestApp(t, config.Config{MaxFileSize: 1 << 20, RateLimitMultiplier: 1}), "203.0.113.10", 11); created != 10 || limited != 1 {
		t.Errorf("multiplier 1: %d created, %d limited; want 10 and 1", created, limited)
	}
	// Raised three times for a test environment.
	if created, limited := createSessions(newTestApp(t, config.Config{MaxFileSize: 1 << 20, RateLimitMultiplier: 3}), "203.0.113.11", 31); created != 30 || limited != 1 {
		t.Errorf("multiplier 3: %d created, %d limited; want 30 and 1", created, limited)
	}
}

func TestApp_TrustedProxyKeysRateLimitOnForwardedClient(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20, TrustedProxies: "10.0.0.0/8"})

	send := func(label, client string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(createSessionBody(t, label)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.RemoteAddr = "10.1.2.3:4321" // the trusted proxy
		req.Header.Set(echo.HeaderXForwardedFor, client)
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := 0; i < 10; i++ {
		if code := send(fmt.Sprintf("client-a-%d", i), "198.51.100.1"); code != http.StatusCreated {
			t.Fatalf("client A request %d: status = %d, want %d", i, code, http.StatusCreated)
		}
	}
	if code := send("client-a-over", "198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("client A over limit: status = %d, want %d", code, http.StatusTooManyRequests)
	}
	// A different client behind the same proxy has its own bucket.
	if code := send("client-b", "198.51.100.2"); code != http.StatusCreated {
		t.Fatalf("client B: status = %d, want %d", code, http.StatusCreated)
	}
}

func TestApp_SessionOperationsDoNotSpendTheCreateBudget(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20})

	// Ten sessions exhaust the create budget.
	sessions := make([]struct{ id, token string }, 0, 10)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(createSessionBody(t, fmt.Sprintf("budget-%d", i))))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create %d: status = %d, want %d", i, rec.Code, http.StatusCreated)
		}
		var body struct {
			SessionID   string `json:"session_id"`
			UploadToken string `json:"upload_token"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode create %d: %v", i, err)
		}
		sessions = append(sessions, struct{ id, token string }{body.SessionID, body.UploadToken})
	}

	// Each of those sessions can still be aborted: that route has its own budget.
	for i, session := range sessions {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/secrets/uploads/"+session.id, nil)
		req.Header.Set(echo.HeaderAuthorization, "Bearer "+session.token)
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("abort %d: status = %d, want %d", i, rec.Code, http.StatusNoContent)
		}
	}
}

func TestApp_RejectsOversizedJSONBody(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 30})

	huge := `{"encrypted_meta":"` + strings.Repeat("A", 256*1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", strings.NewReader(huge))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	app.echo.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusRequestEntityTooLarge)
	}
}

func TestVersionRouteServesTheVersionPassedToNew(t *testing.T) {
	app := newTestApp(t, config.Config{})
	rec := httptest.NewRecorder()

	app.echo.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"version":"test"}` {
		t.Errorf("body = %s, want the version passed to New", body)
	}
}

func TestApp_UntrustedPeerBehindConfiguredProxiesCannotSpoofItsWayPastTheLimit(t *testing.T) {
	// Production trusts the gateway pods only; a peer outside that range
	// keys on its own address whatever it claims.
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20, TrustedProxies: "10.42.0.0/16"})

	var statuses []int
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(createSessionBody(t, fmt.Sprintf("untrusted-%d", i))))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.RemoteAddr = "203.0.113.7:4321"
		req.Header.Set(echo.HeaderXForwardedFor, fmt.Sprintf("198.51.100.%d, 10.42.0.%d", i+1, i+1))
		req.Header.Set(echo.HeaderXRealIP, fmt.Sprintf("198.51.100.%d", i+101))
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		statuses = append(statuses, rec.Code)
	}

	for i, code := range statuses[:10] {
		if code != http.StatusCreated {
			t.Fatalf("request %d: status = %d, want %d", i, code, http.StatusCreated)
		}
	}
	if statuses[10] != http.StatusTooManyRequests {
		t.Fatalf("request 10: status = %d, want %d (rate limit bypassed via forwarding headers)", statuses[10], http.StatusTooManyRequests)
	}
}

func TestApp_RateLimitedResponsesKeepTheirHeaders(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20})

	send := func(i int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/secrets/uploads", bytes.NewReader(createSessionBody(t, fmt.Sprintf("headers-%d", i))))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		return rec
	}

	for i := 0; i < 11; i++ {
		rec := send(i)
		want := http.StatusCreated
		if i == 10 {
			want = http.StatusTooManyRequests
		}
		if rec.Code != want {
			t.Fatalf("request %d: status = %d, want %d", i, rec.Code, want)
		}
		// The API does not announce its limits or the remaining budget.
		for _, header := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining"} {
			if got := rec.Header().Get(header); got != "" {
				t.Errorf("request %d: %s = %q, want none", i, header, got)
			}
		}
		if i == 10 {
			if got := rec.Header().Get("Retry-After"); got != "60" {
				t.Errorf("Retry-After = %q, want 60", got)
			}
			if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"rate limit exceeded"}` {
				t.Errorf("body = %s", body)
			}
		} else if got := rec.Header().Get("Retry-After"); got != "" {
			t.Errorf("request %d: Retry-After = %q, want none", i, got)
		}
	}
}

func TestApp_SmallRequestBodyLimitIs64000Bytes(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 30})

	send := func(size int) int {
		// Not JSON a handler accepts; only whether the limit lets it through
		// matters.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/transfers/claim", strings.NewReader(strings.Repeat(" ", size)))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		app.echo.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := send(64_000); code == http.StatusRequestEntityTooLarge {
		t.Errorf("64000 bytes: status = %d, want it past the limit", code)
	}
	if code := send(64_001); code != http.StatusRequestEntityTooLarge {
		t.Errorf("64001 bytes: status = %d, want %d", code, http.StatusRequestEntityTooLarge)
	}
}

func TestApp_EchoErrorsKeepTheirStatusAndShape(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20})

	tests := []struct {
		name   string
		method string
		path   string
		status int
		body   string
	}{
		{"unknown route", http.MethodGet, "/api/v1/unknown", http.StatusNotFound, `{"error":"Not Found"}`},
		{"unknown route under a group", http.MethodGet, "/api/v1/secrets/" + testPublicID("echo errors") + "/unknown", http.StatusNotFound, `{"error":"Not Found"}`},
		{"wrong method", http.MethodPost, "/api/v1/version", http.StatusMethodNotAllowed, `{"error":"Method Not Allowed"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			app.echo.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if body := strings.TrimSpace(rec.Body.String()); body != tt.body {
				t.Errorf("body = %s, want %s", body, tt.body)
			}
		})
	}
}

func TestApp_HTTPMetricsLabelRouteAndStatus(t *testing.T) {
	app := newTestApp(t, config.Config{MaxFileSize: 1 << 20})
	publicID := testPublicID("metrics")

	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/api/v1/version", nil),
		// A handler's error, written by the error handler.
		httptest.NewRequest(http.MethodGet, "/api/v1/secrets/"+publicID+"/meta", nil),
		// Echo's own errors.
		httptest.NewRequest(http.MethodGet, "/api/v1/unknown/"+publicID, nil),
		httptest.NewRequest(http.MethodPost, "/api/v1/version", nil),
	}
	oversized := httptest.NewRequest(http.MethodPost, "/api/v1/transfers/claim", strings.NewReader(strings.Repeat(" ", 64_001)))
	oversized.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	requests = append(requests, oversized)
	for _, req := range requests {
		app.echo.ServeHTTP(httptest.NewRecorder(), req)
	}

	families, err := app.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "secretli_http_requests_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			got[labels["method"]+" "+labels["route"]+" "+labels["status_code"]] = metric.GetCounter().GetValue()
		}
	}

	want := map[string]float64{
		"GET /api/v1/version 200":                1,
		"GET /api/v1/secrets/:publicID/meta 400": 1,
		"GET /* 404":                             1,
		"POST /api/v1/version 405":               1,
		"POST /api/v1/transfers/claim 413":       1,
	}
	for key, count := range want {
		if got[key] != count {
			t.Errorf("%s: count = %v, want %v (all: %v)", key, got[key], count, got)
		}
	}
	for key := range got {
		if strings.Contains(key, publicID) {
			t.Errorf("metric labels name the public id: %s", key)
		}
	}
}

func TestApp_RejectsInvalidAllowedOrigins(t *testing.T) {
	repo := fullMockRepo{mockSecretRepo: newMockRepo(), uploadMockRepo: newUploadMockRepo(), transferMockRepo: newTransferMockRepo()}
	if _, err := New(config.Config{AllowedOrigins: "https://secretli.app/"}, "test", nil, repo, newUploadMockStore(), nil, prometheus.NewRegistry()); err == nil {
		t.Fatal("expected error for an allowed origin with a path")
	}
	if _, err := New(config.Config{AllowedOrigins: "https://secretli.app, http://localhost:5173"}, "test", nil, repo, newUploadMockStore(), nil, prometheus.NewRegistry()); err != nil {
		t.Fatalf("valid origins: %v", err)
	}
}

func TestApp_PanicIsAnInternalServerError(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	app := newTestApp(t, config.Config{})
	app.echo.GET("/panic", func(*echo.Context) error { panic("boom") })

	rec := httptest.NewRecorder()
	app.echo.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/panic", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"error":"internal server error"}` {
		t.Errorf("body = %s", body)
	}
	if !strings.Contains(logs.String(), "boom") {
		t.Errorf("panic not logged: %s", logs.String())
	}
}
