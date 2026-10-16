package httpserver

import (
	"errors"
	"fmt"

	"github.com/labstack/echo/v5"
	"github.com/secretli/server/internal/domain"
	apperrors "github.com/secretli/server/internal/platform/errors"
)

// storageUnavailableRetryAfter is the Retry-After, in seconds, while storage
// is unavailable.
const storageUnavailableRetryAfter = "10"

// storageFailed answers a failed storage call. While storage is unavailable
// the answer is a 503 with Retry-After, which clients wait out and repeat;
// anything else is a 500. Both are logged with the cause.
func storageFailed(c *echo.Context, msg string, err error) error {
	if errors.Is(err, domain.ErrStorageUnavailable) {
		c.Response().Header().Set("Retry-After", storageUnavailableRetryAfter)
		return &apperrors.Error{
			Type:    apperrors.Unavailable,
			Message: "storage is unavailable right now; try again shortly",
			Cause:   fmt.Errorf("%s: %w", msg, err),
		}
	}
	return apperrors.InternalError(msg, err)
}
