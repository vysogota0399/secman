package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Server struct {
	Router *Router
	srv    *http.Server
	lg     *logging.ZapLogger
}

func NewServer(lc fx.Lifecycle, core *secman.Core, r *Router, lg *logging.ZapLogger) *Server {
	cfg := core.Config.Server
	s := &Server{
		srv:    &http.Server{Addr: cfg.Address, Handler: r.router, ReadHeaderTimeout: time.Minute},
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

	return s
}

func (s *Server) Start(ctx context.Context) error {
	if s.srv.Addr == "" {
		return errors.New("http_server: address is empty")
	}

	ln, err := net.Listen("tcp", s.srv.Addr)
	if err != nil {
		return err
	}

	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	core   *secman.Core
}

func NewRouter(
	core *secman.Core,
	initHandler *Init,
	unsealHandler *Unseal,
) *Router {
	r := &Router{router: gin.New(), core: core}
	api := r.router.Group("/api")
	api.Use(
		gin.Logger(),
		gin.Recovery(),
	)

	api.GET("/sys/status", NewStatus(core).Handler())
	api.POST("/sys/init", initHandler.Handler())

	authorized := api.Group("/")
	authorized.Use(
		r.Authorize,
	)

	{
		sealed := authorized.Group("/")
		sealed.Use(
			r.AbortIfNotInitialized,
		)

		sealed.POST("/sys/unseal", unsealHandler.Handler())
	}

	{
		unsealed := authorized.Group("/")
		unsealed.Use(
			r.AbortIfNotInitialized,
			r.AbortIfSealed,
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
		err := r.core.RootTokens.Compare(c.Request.Context(), secman.RootTokenPath, token)
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
