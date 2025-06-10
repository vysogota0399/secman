package http

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/config"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Server struct {
	Router *Router
	srv    HTTPServer
	lg     *logging.ZapLogger
}

type HTTPServer interface {
	ListenAndServeTLS(certFile, keyFile string) error
	Shutdown(ctx context.Context) error
}

func NewServer(lc fx.Lifecycle, core *server.Core, r *Router, lg *logging.ZapLogger) (*Server, error) {
	cfg := core.Config.Server

	httpServer := &http.Server{
		Addr:        cfg.Address,
		Handler:     r.router,
		ReadTimeout: time.Minute,
	}

	if cfg.Address == "" {
		return nil, errors.New("http_server: address is empty")
	}

	tlsCfg, err := prepareTLS(core.Config)
	if err != nil {
		return nil, err
	}

	httpServer.TLSConfig = tlsCfg

	s := &Server{
		srv:    httpServer,
		Router: r,
		lg:     lg,
	}

	lc.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				return s.Start(ctx)
			},
			OnStop: func(ctx context.Context) error {
				return s.Shutdown(ctx)
			},
		},
	)

	return s, nil
}

func (s *Server) Start(ctx context.Context) error {
	go func() {
		if err := s.srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.lg.ErrorCtx(ctx, "http_server: serve failer error", zap.Error(err))
		}
	}()

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

type Route struct {
	Handler       gin.HandlerFunc
	Path          string
	Method        string
	HTMLTemplates []*template.Template
}

type Router struct {
	router *gin.Engine
	core   *server.Core
}

func NewRouter(
	core *server.Core,
	coreRepository server.ICoreRepository,
) *Router {
	r := &Router{router: gin.New(), core: core}
	api := r.router.Group("/api")
	api.Use(
		gin.Logger(),
		gin.Recovery(),
	)

	api.GET("/sys/status", NewStatus(core).Handler())
	api.POST("/sys/init", NewInit(core, coreRepository).Handler())

	// Sealed routes available when the server is sealed
	// authorize is required
	{
		sealed := api.Group("/")
		sealed.Use(
			r.AbortIfNotInitialized,
			r.Authorize,
		)

		sealed.POST("/sys/unseal", NewUnseal(core).Handler())
	}

	// Unsealed routes, only available when the server is unsealed
	// authorize is required
	{
		unsealed := api.Group("/")

		unsealed.Use(
			r.AbortIfNotInitialized,
			r.AbortIfSealed,
			r.Authorize,
		)

		unsealed.POST("/sys/engines/enable/*engine_path", NewEnableEngine(core).Handler())
		unsealed.POST("/sys/auth/enable", NewEnableAuth(core).Handler())

		unsealed.Any("/engine/*path", NewEngine(core).Handler())
	}

	return r
}

func (r *Router) AbortIfSealed(c *gin.Context) {
	if r.core.IsSealed.Load() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "server is sealed"})
		return
	}

	c.Next()
}

func (r *Router) AbortIfNotInitialized(c *gin.Context) {
	if !r.core.IsInitialized.Load() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "server is not initialized"})
	}
}

func (r *Router) Authorize(c *gin.Context) {
	token := c.GetHeader("X-Secman-Token")
	if token != "" {
		err := r.core.RootTokens.Compare(c.Request.Context(), server.RootTokenKey, token)
		if err != nil {
			r.core.Log.DebugCtx(c.Request.Context(), "authorize failed", zap.String("error", err.Error()))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Next()
		return
	}

	if err := r.core.Auth.Authorize(c); err != nil {
		r.core.Log.DebugCtx(c.Request.Context(), "authorize failed", zap.String("error", err.Error()))
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	c.Next()
}

func prepareTLS(cfg *config.Config) (*tls.Config, error) {
	serverTLSCert, err := tls.LoadX509KeyPair(
		cfg.Server.CertPath,
		cfg.Server.KeyPath,
	)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
	}

	return tlsConfig, nil
}
