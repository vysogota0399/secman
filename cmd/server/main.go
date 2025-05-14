package main

import (
	"context"
	"os"

	"github.com/vysogota0399/secman/internal/engines/logopass"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/bariers"
	"github.com/vysogota0399/secman/internal/secman/config"
	"github.com/vysogota0399/secman/internal/secman/http"
	"github.com/vysogota0399/secman/internal/secman/iam"
	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
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
			AsEngines(logopass.NewEngine),
			fx.Annotate(logopass.NewLogopass, fx.As(new(logopass.IamAdapter))),

			fx.Annotate(iam.NewCore, fx.As(new(logopass.Iam))),
			fx.Annotate(iam_repositories.NewSessions, fx.As(new(iam.SessionsRepository))),
			fx.Annotate(iam_repositories.NewUsers, fx.As(new(iam.UsersRepository))),

			fx.Annotate(config.NewConfig, fx.As(new(logging.LogLevelFetcher))),

			logging.MustZapLogger,
			secman.NewEnginesMap,
			secman.NewCoreRepository,
			fx.Annotate(secman.NewCore, fx.ParamTags(`group:"engines"`)),

			http.NewRouter,
			http.NewServer,
			http.NewInit,

			fx.Annotate(storages.NewStorage, fx.As(new(secman.IStorage))),
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
		zap.Int("pid", os.Getpid()),
	)
}

func runServer(server *http.Server) {}

func AsEngines(f any, ants ...fx.Annotation) any {
	ants = append(ants, fx.ResultTags(`group:"engines"`))
	ants = append(ants, fx.As(new(secman.Engine)))

	return fx.Annotate(
		f,
		ants...,
	)
}
