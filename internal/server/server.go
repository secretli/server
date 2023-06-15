package server

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/secretli/server/internal"
	"github.com/secretli/server/internal/config"
	"net/http"
)

const (
	HeaderRetrievalToken = "X-Retrieval-Token"
	HeaderDeletionToken  = "X-Deletion-Token"
)

type Server struct {
	*gin.Engine
	config  config.Configuration
	secrets internal.SecretService
}

func NewServer(config config.Configuration, secretService internal.SecretService) *Server {
	svr := &Server{
		Engine:  gin.New(),
		config:  config,
		secrets: secretService,
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
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		var request internal.StoreSecretParameters
		if err := c.BindJSON(&request); err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}

		err := s.secrets.Store(ctx, request)
		if errors.Is(err, internal.ErrInvalidExpiration) {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		if errors.Is(err, internal.ErrInvalidEncryptedData) {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
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
		ctx := c.Request.Context()

		id := c.Param("id")
		retrievalToken := c.GetHeader(HeaderRetrievalToken)

		params := internal.RetrieveSecretParameters{SecretID: id, RetrievalToken: retrievalToken}
		secret, err := s.secrets.Retrieve(ctx, params)
		if errors.Is(err, internal.ErrUnknownSecret) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if errors.Is(err, internal.ErrInaccessibleSecret) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if errors.Is(err, internal.ErrAuthorizationFailed) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err != nil {
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
		ctx := c.Request.Context()

		params := internal.DeleteSecretParameters{
			SecretID:       c.Param("id"),
			RetrievalToken: c.GetHeader(HeaderRetrievalToken),
			DeletionToken:  c.GetHeader(HeaderDeletionToken),
		}

		err := s.secrets.Delete(ctx, params)
		if errors.Is(err, internal.ErrUnknownSecret) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if errors.Is(err, internal.ErrAuthorizationFailed) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		c.Status(http.StatusOK)
	}
}
