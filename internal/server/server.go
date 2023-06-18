package server

import (
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
	type request struct {
		PublicID       string `json:"public_id"`
		RetrievalToken string `json:"retrieval_token"`
		DeletionToken  string `json:"deletion_token"`
		Nonce          string `json:"nonce"`
		EncryptedData  string `json:"encrypted_data"`
		Expiration     string `json:"expiration"`
		BurnAfterRead  bool   `json:"burn_after_read"`
	}

	return func(c *gin.Context) {
		var r request
		if err := c.BindJSON(&r); err != nil {
			_ = c.Error(internal.ErrInvalidJSON).SetType(gin.ErrorTypePublic)
			return
		}

		secret, err := internal.NewSecret(internal.SecretSpecification{
			PublicID:       r.PublicID,
			RetrievalToken: r.RetrievalToken,
			DeletionToken:  r.DeletionToken,
			Nonce:          r.Nonce,
			EncryptedData:  r.EncryptedData,
			Expiration:     r.Expiration,
			BurnAfterRead:  r.BurnAfterRead,
		})
		if err != nil {
			_ = c.Error(err).SetType(gin.ErrorTypePublic)
			return
		}

		ctx := c.Request.Context()
		if err = s.secrets.Store(ctx, secret); err != nil {
			_ = c.Error(err).SetType(gin.ErrorTypePublic)
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
		token := c.GetHeader(HeaderRetrievalToken)

		secret, err := s.secrets.Retrieve(ctx, id, token)
		if err != nil {
			_ = c.Error(err).SetType(gin.ErrorTypePublic)
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

		id := c.Param("id")
		rt := c.GetHeader(HeaderRetrievalToken)
		dt := c.GetHeader(HeaderDeletionToken)

		err := s.secrets.Delete(ctx, id, rt, dt)
		if err != nil {
			_ = c.Error(err).SetType(gin.ErrorTypePublic)
			return
		}

		c.Status(http.StatusOK)
	}
}
