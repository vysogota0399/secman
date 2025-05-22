package main

import (
	"context"
	"os"

	"github.com/vysogota0399/secman/internal/engines/blobs"
	"github.com/vysogota0399/secman/internal/engines/kv"
	"github.com/vysogota0399/secman/internal/engines/logopass"
	logopass_repositories "github.com/vysogota0399/secman/internal/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/engines/pci_dss"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/bariers"
	"github.com/vysogota0399/secman/internal/secman/config"

	"github.com/vysogota0399/secman/internal/secman/http"
	"github.com/vysogota0399/secman/internal/secman/iam"
	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
	"github.com/vysogota0399/secman/internal/secman/storages"
	"github.com/vysogota0399/secman/internal/secman/tokens"
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
			logging.MustZapLogger,
			fx.Annotate(config.NewConfig, fx.As(new(logging.LogLevelFetcher))),

			// engines
			AsBackend(logopass.NewBackend),
			logopass.NewLogopass,
			fx.Annotate(logopass_repositories.NewParamsRepository, fx.As(new(logopass.ParamsRepository))),

			AsBackend(kv.NewBackend),
			kv.NewRepository,
			kv.NewMetadataRepository,

			AsBackend(pci_dss.NewBackend),
			pci_dss.NewRepository,
			pci_dss.NewMetadataRepository,

			AsBackend(blobs.NewBackend),
			blobs.NewRepository,
			blobs.NewMetadataRepository,

			// iam
			fx.Annotate(iam_repositories.NewSessions, fx.As(new(iam.SessionsRepository))),
			fx.Annotate(iam_repositories.NewUsers, fx.As(new(iam.UsersRepository))),
			fx.Annotate(iam.NewCore,
				fx.As(new(logopass.IamAdapter)),
			),

			// tokens
			tokens.NewTokensRepository,
			fx.Annotate(tokens.NewRootToken, fx.As(new(secman.IRootTokens))),

			// core
			fx.Annotate(secman.NewCore),
			secman.NewCoreRepository,
			fx.Annotate(storages.NewStorage,
				fx.As(new(secman.IStorage)),
			),
			fx.Annotate(secman.NewLogicalRouter, fx.ParamTags(`group:"backends"`)),
			fx.Annotate(bariers.NewDummyBarrier, fx.As(new(secman.IBarrier))),
			secman.NewAuth,

			// http
			http.NewRouter,
			http.NewServer,
			http.NewInit,
			fx.Annotate(http.NewUnseal),
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

func AsBackend(f any, ants ...fx.Annotation) any {
	ants = append(ants, fx.ResultTags(`group:"backends"`))
	ants = append(ants, fx.As(new(secman.LogicalBackend)))

	return fx.Annotate(
		f,
		ants...,
	)
}
