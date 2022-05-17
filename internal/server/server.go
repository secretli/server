package server

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/config"
	"net/http"
	"time"
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
	base.GET("/health", s.handleHealth())

	api := base.Group("api")
	{
		api.POST("secret", s.storeSecret())
		api.POST("secret/:id", s.retrieveSecret())
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
	}

	return func(c *gin.Context) {
		var r request
		if err := c.BindJSON(&r); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		expiresAt := time.Now()

		switch r.Expiration {
		case "5min":
			expiresAt = expiresAt.Add(5 * time.Minute)
		default:
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		secret := internal.Secret{
			PublicID:       r.PublicID,
			RetrievalToken: r.RetrievalToken,
			Nonce:          r.Nonce,
			EncryptedData:  r.EncryptedData,
			ExpiresAt:      expiresAt,
		}

		ctx := c.Request.Context()
		err := s.repo.Store(ctx, secret)
		if err != nil {
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
		retrievalToken := c.GetHeader("X-Retrieval-Token")

		ctx := c.Request.Context()
		secret, err := s.repo.Get(ctx, id)
		if err != nil {
			if errors.Is(err, internal.ErrUnknownSecret) {
				c.AbortWithStatus(http.StatusNotFound)
				return
			}

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

		c.JSON(http.StatusOK, response{
			Nonce:         secret.Nonce,
			EncryptedData: secret.EncryptedData,
		})
	}
}
