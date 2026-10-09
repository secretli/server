package httpserver

import (
	"context"
	"fmt"
	"log/slog"
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
	addr           string
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

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = httpErrorHandler
	// Never trust client-supplied X-Forwarded-For unless a proxy is configured;
	// the rate limiters key on the client IP.
	e.IPExtractor = ipExtractor

	e.Server.ReadHeaderTimeout = 10 * time.Second
	e.Server.ReadTimeout = 30 * time.Minute
	e.Server.WriteTimeout = 30 * time.Minute
	e.Server.IdleTimeout = 120 * time.Second

	a := &App{
		echo:           e,
		addr:           fmt.Sprintf(":%s", cfg.Port),
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
	a.SecretMetrics = a.registerRoutes()

	return a, nil
}

func (a *App) Start() error {
	return a.echo.Start(a.addr)
}

func (a *App) Shutdown(ctx context.Context) error {
	return a.echo.Shutdown(ctx)
}
