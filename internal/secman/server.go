package secman

import (
	"context"
	"errors"
	"html/template"
	"net"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Route struct {
	Handler       gin.HandlerFunc
	Path          string
	Method        string
	HTMLTemplates []*template.Template
}

type Router struct {
	router *gin.Engine
}

type HTTPServer struct {
	Router *Router
	srv    *http.Server
	cfg    *Config
	lg     *logging.ZapLogger
}

func NewHTTPServer(lc fx.Lifecycle, cfg *Config, r *Router, lg *logging.ZapLogger) *HTTPServer {
	s := &HTTPServer{
		srv:    &http.Server{Addr: cfg.Address, Handler: r.router, ReadHeaderTimeout: time.Minute},
		Router: r,
		cfg:    cfg,
		lg:     lg,
	}

	lc.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				lg.InfoCtx(ctx, "Starting HTTP server", zap.Any("cfg", s.cfg))
				return s.Start(ctx)
			},
			OnStop: func(ctx context.Context) error {
				return s.Shutdown(ctx)
			},
		},
	)

	return s
}

func (s *HTTPServer) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Address)
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

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}
