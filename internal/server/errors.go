package server

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/secretli/server/internal"
	"net/http"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		err := c.Errors.Last()
		if err == nil {
			return
		}

		status := http.StatusInternalServerError
		for e, s := range mapping {
			if errors.Is(err, e) {
				status = s
				break
			}
		}

		c.Status(status)
	}
}

var mapping = map[error]int{
	internal.ErrUnknownSecret:        http.StatusNotFound,
	internal.ErrInaccessibleSecret:   http.StatusNotFound,
	internal.ErrAuthorizationFailed:  http.StatusForbidden,
	internal.ErrInvalidExpiration:    http.StatusBadRequest,
	internal.ErrInvalidEncryptedData: http.StatusBadGateway,
}
