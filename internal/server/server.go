package server

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/config"
	"net/http"
	"time"
)

const (
	Day = 24 * time.Hour

	HeaderRetrievalToken = "X-Retrieval-Token"
	HeaderDeletionToken  = "X-Deletion-Token"
)

type Server struct {
	*gin.Engine

	// shared components
	config config.Configuration

	// services & more
	repo internal.SecretRepository
}

func NewServer(config config.Configuration, repo internal.SecretRepository) *Server {
	svr := &Server{
		Engine: gin.New(),
		config: config,
		repo:   repo,
	}

	_ = svr.SetTrustedProxies(nil)

	return svr
}

func (s *Server) InitRoutes() {
	base := s.Group(s.config.ForwardedPrefix)
	{
		base.GET("health", s.handleHealth())
		base.POST("secret", s.storeSecret())
		base.POST("secret/:id", s.retrieveSecret())
		base.DELETE("secret/:id", s.deleteSecret())
	}
}

func (s *Server) handleHealth() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Status(http.StatusOK)
	}
}

func (s *Server) storeSecret() gin.HandlerFunc {
	type request struct {
		PublicID       string `json:"public_id"`
		RetrievalToken string `json:"retrieval_token"`
		Nonce          string `json:"nonce"`
		EncryptedData  string `json:"encrypted_data"`
		Expiration     string `json:"expiration"`
		BurnAfterRead  bool   `json:"burn_after_read"`
		DeletionToken  string `json:"deletion_token"`
	}

	return func(c *gin.Context) {
		var r request
		if err := c.BindJSON(&r); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		if len(r.EncryptedData) > 10000 {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		expiration, err := processExpirationDuration(r.Expiration)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		secret := internal.Secret{
			PublicID:       r.PublicID,
			RetrievalToken: r.RetrievalToken,
			Nonce:          r.Nonce,
			EncryptedData:  r.EncryptedData,
			ExpiresAt:      time.Now().Add(expiration),
			BurnAfterRead:  r.BurnAfterRead,
			AlreadyRead:    false,
			DeletionToken:  r.DeletionToken,
		}

		ctx := c.Request.Context()
		if err := s.repo.Store(ctx, secret); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusCreated)
	}
}

func (s *Server) retrieveSecret() gin.HandlerFunc {
	type response struct {
		Nonce         string `json:"nonce"`
		EncryptedData string `json:"encrypted_data"`
	}

	return func(c *gin.Context) {
		id := c.Param("id")
		retrievalToken := c.GetHeader(HeaderRetrievalToken)

		ctx := c.Request.Context()
		secret, err := s.repo.Get(ctx, id)
		if errors.Is(err, internal.ErrUnknownSecret) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if secret.ExpiresAt.Before(time.Now()) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if secret.RetrievalToken != retrievalToken {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		if secret.BurnAfterRead && secret.AlreadyRead {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}

		if err := s.repo.MarkAsRead(ctx, id); err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.JSON(http.StatusOK, response{
			Nonce:         secret.Nonce,
			EncryptedData: secret.EncryptedData,
		})
	}
}

func (s *Server) deleteSecret() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		ctx := c.Request.Context()
		secret, err := s.repo.Get(ctx, id)
		if errors.Is(err, internal.ErrUnknownSecret) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if secret.DeletionToken == "" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		rt := c.GetHeader(HeaderRetrievalToken)
		dt := c.GetHeader(HeaderDeletionToken)
		if secret.RetrievalToken != rt || secret.DeletionToken != dt {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}

		err = s.repo.Delete(ctx, id)
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusOK)
	}
}

func processExpirationDuration(expiration string) (time.Duration, error) {
	var duration time.Duration

	switch expiration {
	case "5m":
		duration = 5 * time.Minute
	case "10m":
		duration = 10 * time.Minute
	case "15m":
		duration = 15 * time.Minute
	case "1h":
		duration = 1 * time.Hour
	case "4h":
		duration = 4 * time.Hour
	case "12h":
		duration = 12 * time.Hour
	case "1d":
		duration = 1 * Day
	case "3d":
		duration = 3 * Day
	case "7d":
		duration = 7 * Day
	default:
		return 0, errors.New("invalid expiration")
	}

	return duration, nil
}
