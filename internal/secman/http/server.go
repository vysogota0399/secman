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
	"github.com/vysogota0399/secman/internal/secman/iam"
	iam_repo "github.com/vysogota0399/secman/internal/secman/iam/repositories"
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

type Authorizer interface {
	Authorize(ctx context.Context, token string) (iam_repo.Session, error)
}

var _ Authorizer = &iam.Core{}

type Router struct {
	router *gin.Engine
	core   *secman.Core
	auth   Authorizer
}

func NewRouter(
	core *secman.Core,
	initHandler *Init,
	auth Authorizer,
) *Router {
	r := &Router{router: gin.New(), core: core, auth: auth}
	api := r.router.Group("/api")
	api.Use(
		gin.Logger(),
		gin.Recovery(),
	)

	api.GET("/sys/status", NewStatus(core).Handler())
	api.POST("/sys/init", initHandler.Handler())
	api.POST("/sys/unseal", NewUnseal(core).Handler())

	authorized := api.Group("/")
	authorized.Use(
		r.Authorize,
	)

	{
		unsealed := authorized.Group("/")
		unsealed.Use(
			r.AbortIfNotInitialized,
			r.AbortIfSealed,
		)

		unsealed.POST("/sys/enable/:engine", NewEnable(core).Handler())

		crud := NewCrud(core)
		unsealed.DELETE("/engine/*path", crud.Handler())
		unsealed.PUT("/engine/*path", crud.Handler())
		unsealed.POST("/engine/*path", crud.Handler())
		unsealed.GET("/engine/*path", crud.Handler())
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
	token := c.GetHeader("X-Vault-Token")
	if token != "" {
		sess, err := r.auth.Authorize(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set("session", sess)
		c.Next()
		return
	}

	c.AbortWithStatus(http.StatusUnauthorized)
}
