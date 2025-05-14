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
	initEnineHandler *Init,
) *Router {
	r := &Router{router: gin.New(), core: core}
	api := r.router.Group("/api")
	api.Use(
		gin.Logger(),
		gin.Recovery(),
	)

	{
		sealed := api.Group("/")
		sealed.POST("/sys/init", initEnineHandler.Handler())
		sealed.POST("/sys/unseal", NewUnseal(core).Handler())
		sealed.GET("/sys/status", NewStatus(core).Handler())
	}

	{
		r1 := api.Group("/")
		r1.Use(
			r.AbortIfNotInitialized,
			r.AbortIfSealed,
		)

		r1.POST("/sys/enable/:engine", NewEnable(core).Handler())

		crud := NewCrud(core)
		r1.DELETE("/engine/*path", crud.Handler())
		r1.PUT("/engine/*path", crud.Handler())
		r1.POST("/engine/*path", crud.Handler())
		r1.GET("/engine/*path", crud.Handler())
	}

	return r
}

func (r *Router) AbortIfSealed(c *gin.Context) {
	if r.core.IsSealed() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "server is sealed"})
		return
	}

	c.Next()
}

func (r *Router) AbortIfNotInitialized(c *gin.Context) {
	if !r.core.IsInitialized() {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "server is not initialized"})
	}
}
