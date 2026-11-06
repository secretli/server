package s3

import (
	"time"

	platformconfig "github.com/secretli/server/internal/platform/config"
)

// NewClientWithAttemptTimeout is NewClient with another attemptTimeout, so a
// test can stall storage for less than the real one.
func NewClientWithAttemptTimeout(cfg platformconfig.S3Config, timeout time.Duration) (*Client, error) {
	return newClient(cfg, timeout)
}
