package config

import (
	"testing"
	"time"
)

// setRequiredEnv sets the required env vars so Load() doesn't fail.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	t.Setenv("S3_ENDPOINT", "http://localhost:9000")
	t.Setenv("S3_BUCKET", "secretli")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
}

func TestLoadDefaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Port != "8080" {
		t.Errorf("Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.S3.Region != "us-east-1" {
		t.Errorf("S3Region = %q, want %q", cfg.S3.Region, "us-east-1")
	}
	if cfg.MaxFileSize != 1073741824 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 1073741824)
	}
	if cfg.CleanupInterval != time.Minute {
		t.Errorf("CleanupInterval = %v, want %v", cfg.CleanupInterval, time.Minute)
	}
	if cfg.MetricsToken != "" {
		t.Errorf("MetricsToken = %q, want empty", cfg.MetricsToken)
	}
	if cfg.TrustedProxies != "" {
		t.Errorf("TrustedProxies = %q, want empty", cfg.TrustedProxies)
	}
	if cfg.RateLimitMultiplier != 1 {
		t.Errorf("RateLimitMultiplier = %d, want 1", cfg.RateLimitMultiplier)
	}
}

func TestLoadRateLimitMultiplier(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("RATE_LIMIT_MULTIPLIER", "100")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.RateLimitMultiplier != 100 {
		t.Errorf("RateLimitMultiplier = %d, want 100", cfg.RateLimitMultiplier)
	}
}

// A mistyped multiplier stops the server instead of starting it with limits
// nobody intended.
func TestLoadRejectsInvalidRateLimitMultiplier(t *testing.T) {
	for _, value := range []string{"0", "-1", "1.5", "lots", ""} {
		t.Run(value, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("RATE_LIMIT_MULTIPLIER", value)
			if _, err := Load(); err == nil {
				t.Errorf("RATE_LIMIT_MULTIPLIER=%q: Load() succeeded, want an error", value)
			}
		})
	}
}

func TestLoadFromEnv(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SERVER_PORT", "9090")
	t.Setenv("S3_ENDPOINT", "https://fsn1.your-objectstorage.com")
	t.Setenv("S3_BUCKET", "my-bucket")
	t.Setenv("MAX_FILE_SIZE", "5242880")
	t.Setenv("CLEANUP_INTERVAL", "5m")
	t.Setenv("METRICS_TOKEN", "metrics-secret")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8,172.16.0.1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Port != "9090" {
		t.Errorf("Port = %q, want %q", cfg.Port, "9090")
	}
	if cfg.S3.Bucket != "my-bucket" {
		t.Errorf("S3Bucket = %q, want %q", cfg.S3.Bucket, "my-bucket")
	}
	if cfg.S3.Endpoint != "https://fsn1.your-objectstorage.com" {
		t.Errorf("S3Endpoint = %q, want %q", cfg.S3.Endpoint, "https://fsn1.your-objectstorage.com")
	}
	if cfg.MaxFileSize != 5242880 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 5242880)
	}
	if cfg.CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, want %v", cfg.CleanupInterval, 5*time.Minute)
	}
	if cfg.MetricsToken != "metrics-secret" {
		t.Errorf("MetricsToken = %q, want %q", cfg.MetricsToken, "metrics-secret")
	}
	if cfg.TrustedProxies != "10.0.0.0/8,172.16.0.1" {
		t.Errorf("TrustedProxies = %q, want %q", cfg.TrustedProxies, "10.0.0.0/8,172.16.0.1")
	}
}

func TestLoadMissingRequiredReturnsError(t *testing.T) {
	// No required env vars set — should fail
	_, err := Load()
	if err == nil {
		t.Error("Load() should return error when required env vars are missing")
	}
}

func TestLoadInvalidEnvReturnsError(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("MAX_FILE_SIZE", "lots")

	_, err := Load()
	if err == nil {
		t.Error("Load() should return error for an invalid number")
	}
}

// Whether the server speaks HTTP or HTTPS to S3 comes from the endpoint's
// scheme alone, so an endpoint without one stops the server.
func TestLoadRejectsEndpointWithoutScheme(t *testing.T) {
	for _, value := range []string{"localhost:8333", "fsn1.your-objectstorage.com", "ftp://localhost:8333", "https://", ""} {
		t.Run(value, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("S3_ENDPOINT", value)
			if _, err := Load(); err == nil {
				t.Errorf("S3_ENDPOINT=%q: Load() succeeded, want an error", value)
			}
		})
	}
}

// There is no default bucket: a bucket of that name could belong to anyone.
func TestLoadRequiresBucket(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://test:test@localhost:5432/test")
	t.Setenv("S3_ENDPOINT", "http://localhost:9000")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	if _, err := Load(); err == nil {
		t.Error("Load() succeeded without S3_BUCKET, want an error")
	}
}

func TestLoadUploadBudget(t *testing.T) {
	setRequiredEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.UploadBudgetBytesPerHour != 4*1024*1024*1024 {
		t.Errorf("UploadBudgetBytesPerHour = %d, want 4 GiB", cfg.UploadBudgetBytesPerHour)
	}

	t.Setenv("UPLOAD_BUDGET_BYTES_PER_HOUR", "0")
	if cfg, err := Load(); err != nil || cfg.UploadBudgetBytesPerHour != 0 {
		t.Errorf("a budget of 0 (off): %d, %v", cfg.UploadBudgetBytesPerHour, err)
	}
}

func TestLoadRejectsAnUploadBudgetBelowTheLargestUpload(t *testing.T) {
	for _, value := range []string{"-1", "1073741823"} {
		t.Run(value, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv("MAX_FILE_SIZE", "1073741824")
			t.Setenv("UPLOAD_BUDGET_BYTES_PER_HOUR", value)
			if _, err := Load(); err == nil {
				t.Errorf("Load() accepted UPLOAD_BUDGET_BYTES_PER_HOUR=%s", value)
			}
		})
	}
}
