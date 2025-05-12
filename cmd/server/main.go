package main

import (
	"context"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/auth"
	"github.com/vysogota0399/secman/internal/secman/bariers"
	"github.com/vysogota0399/secman/internal/secman/config"
	"github.com/vysogota0399/secman/internal/secman/http"
	"github.com/vysogota0399/secman/internal/secman/repositories"
	"github.com/vysogota0399/secman/internal/secman/storages"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	BuildVersion string = "N/A"
	BuildDate    string = "N/A"
	BuildCommit  string = "N/A"
)

func main() {
	fx.New(CreateApp()).Run()
}

func CreateApp() fx.Option {
	return fx.Options(
		fx.Provide(
			config.NewConfig,
			fx.Annotate(config.NewConfig, fx.As(new(logging.LogLevelFetcher))),

			logging.MustZapLogger,
			secman.NewCore,
			http.NewRouter,
			http.NewServer,

			fx.Annotate(repositories.NewSessions, fx.As(new(auth.SessionsRepository))),
			fx.Annotate(repositories.NewUsers, fx.As(new(auth.UsersRepository))),

			fx.Annotate(storages.NewStorage, fx.As(new(secman.IStorage))),
			fx.Annotate(auth.NewAuth, fx.As(new(secman.IAuth))),
			fx.Annotate(bariers.NewDummyBarrier, fx.As(new(secman.IBarrier))),
		),
		fx.Invoke(
			info,
			runServer,
		),
	)
}

func info(lg *logging.ZapLogger) {
	lg.InfoCtx(context.Background(), "Build info",
		zap.String("version", BuildVersion),
		zap.String("date", BuildDate),
		zap.String("commit", BuildCommit),
	)
}

func runServer(server *http.Server) {}
