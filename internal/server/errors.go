package server

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/secretli/server/internal"
	"net/http"
	"schneider.vip/problem"
)

func ErrorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()

		err := c.Errors.ByType(gin.ErrorTypePublic).Last()
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

		if _, err := problem.Of(status).WriteTo(c.Writer); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
		}
	}
}

var mapping = map[error]int{
	internal.ErrUnknownSecret:        http.StatusNotFound,
	internal.ErrInaccessibleSecret:   http.StatusNotFound,
	internal.ErrAuthorizationFailed:  http.StatusForbidden,
	internal.ErrInvalidJSON:          http.StatusBadRequest,
	internal.ErrInvalidExpiration:    http.StatusBadRequest,
	internal.ErrInvalidEncryptedData: http.StatusBadGateway,
}
