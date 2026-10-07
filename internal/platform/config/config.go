package config

import (
	"fmt"
	"time"

	"github.com/joho/godotenv"
	"go-simpler.org/env"
)

type S3Config struct {
	Endpoint  string `env:"ENDPOINT,required"`
	Bucket    string `env:"BUCKET" default:"secretli"`
	AccessKey string `env:"ACCESS_KEY,required"`
	SecretKey string `env:"SECRET_KEY,required"`
	UseSSL    bool   `env:"USE_SSL" default:"true"`
	Region    string `env:"REGION" default:"us-east-1"`
}

type Config struct {
	Port            string        `env:"SERVER_PORT" default:"8080"`
	DatabaseURL     string        `env:"DATABASE_URL,required"`
	S3              S3Config      `env:"S3"`
	MaxFileSize     int64         `env:"MAX_FILE_SIZE" default:"1073741824"`
	CleanupInterval time.Duration `env:"CLEANUP_INTERVAL" default:"1m"`
	AllowedOrigins  string        `env:"ALLOWED_ORIGINS"`
	MetricsToken    string        `env:"METRICS_TOKEN"`
	// TrustedProxies is a comma-separated list of IPs or CIDRs of reverse
	// proxies whose X-Forwarded-For headers may be trusted for client IP
	// resolution. When empty, forwarding headers are ignored entirely.
	TrustedProxies string `env:"TRUSTED_PROXIES"`
	// RateLimitMultiplier raises every rate limit by this factor, for test
	// environments that send more requests from one address than a visitor
	// would. It is read once at startup and never from a request; production
	// leaves it at 1.
	RateLimitMultiplier int `env:"RATE_LIMIT_MULTIPLIER" default:"1"`
}

func Load() (Config, error) {
	_ = godotenv.Load() // ignore missing .env
	var cfg Config
	if err := env.Load(&cfg, &env.Options{NameSep: "_"}); err != nil {
		return Config{}, err
	}
	if cfg.RateLimitMultiplier < 1 {
		return Config{}, fmt.Errorf("RATE_LIMIT_MULTIPLIER must be a whole number of at least 1, got %d", cfg.RateLimitMultiplier)
	}
	return cfg, nil
}
