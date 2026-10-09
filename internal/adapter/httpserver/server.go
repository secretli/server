package httpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/secretli/server/internal/adapter/metrics"
	"github.com/secretli/server/internal/domain"
	"github.com/secretli/server/internal/platform/config"
)

type App struct {
	echo           *echo.Echo
	server         *http.Server
	pool           *pgxpool.Pool
	secretRepo     domain.Repo
	fileStore      domain.MultipartFileStore
	transferEvents TransferEvents
	cfg            config.Config
	version        string
	reg            *prometheus.Registry

	SecretMetrics *metrics.SecretMetrics
}

// New builds the app. transferEvents may be nil; transfer long-polls then
// poll the database.
func New(cfg config.Config, version string, pool *pgxpool.Pool, secretRepo domain.Repo, fileStore domain.MultipartFileStore, transferEvents TransferEvents, reg *prometheus.Registry) (*App, error) {
	ipExtractor, err := newIPExtractor(cfg.TrustedProxies)
	if err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}

	e := echo.NewWithConfig(echo.Config{
		// Echo's own messages go through the correlated application logger.
		Logger:           slog.Default(),
		HTTPErrorHandler: httpErrorHandler,
		// Never trust client-supplied X-Forwarded-For unless a proxy is
		// configured; the rate limiters key on the client IP.
		IPExtractor: ipExtractor,
	})

	a := &App{
		echo: e,
		// Echo v5 leaves the server to the caller, so the app keeps its own
		// with the timeouts it always had.
		server: &http.Server{
			Addr:              fmt.Sprintf(":%s", cfg.Port),
			Handler:           e,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Minute,
			WriteTimeout:      30 * time.Minute,
			IdleTimeout:       120 * time.Second,
			ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		},
		pool:           pool,
		secretRepo:     secretRepo,
		fileStore:      fileStore,
		transferEvents: transferEvents,
		cfg:            cfg,
		version:        version,
		reg:            reg,
	}

	if cfg.RateLimitMultiplier > 1 {
		slog.Warn("rate limits are raised for testing; production must not set RATE_LIMIT_MULTIPLIER",
			"multiplier", cfg.RateLimitMultiplier)
	}
	secretMetrics, err := a.registerRoutes()
	if err != nil {
		return nil, err
	}
	a.SecretMetrics = secretMetrics

	return a, nil
}

// Start serves until Shutdown, then returns http.ErrServerClosed.
func (a *App) Start() error {
	return a.server.ListenAndServe()
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}
