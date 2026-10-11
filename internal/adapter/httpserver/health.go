package httpserver

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v5"
)

type healthResponse struct {
	Status string `json:"status"`
}

type Pinger interface {
	Ping(ctx context.Context) error
}

func Liveness(c *echo.Context) error {
	return c.JSON(http.StatusOK, healthResponse{Status: "ok"})
}

// readyFor is how long a successful database ping answers the readiness
// check without another. The check can't be rate limited: a 429 to the
// kubelet would take the pod out of service. Reusing a fresh result keeps a
// flood of checks from becoming a flood of pings.
const readyFor = time.Second

func ReadinessWithDB(pinger Pinger) echo.HandlerFunc {
	return readiness(pinger, readyFor, time.Now)
}

func readiness(pinger Pinger, fresh time.Duration, now func() time.Time) echo.HandlerFunc {
	// When the last ping succeeded, in Unix nanoseconds; 0 for never.
	var lastOK atomic.Int64
	return func(c *echo.Context) error {
		if last := lastOK.Load(); last != 0 && now().Sub(time.Unix(0, last)) < fresh {
			return c.JSON(http.StatusOK, healthResponse{Status: "ok"})
		}
		if err := pinger.Ping(c.Request().Context()); err != nil {
			return c.JSON(http.StatusServiceUnavailable, healthResponse{Status: "unavailable"})
		}
		lastOK.Store(now().UnixNano())
		return c.JSON(http.StatusOK, healthResponse{Status: "ok"})
	}
}
