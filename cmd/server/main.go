package main

import (
	"context"
	"os"

	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/engines/blobs"
	"github.com/vysogota0399/secman/internal/server/engines/kv"
	"github.com/vysogota0399/secman/internal/server/engines/logopass"
	logopass_repositories "github.com/vysogota0399/secman/internal/server/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/server/engines/pcidss"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server/bariers"
	"github.com/vysogota0399/secman/internal/server/config"

	"github.com/vysogota0399/secman/internal/server/http"
	"github.com/vysogota0399/secman/internal/server/iam"
	iam_repositories "github.com/vysogota0399/secman/internal/server/iam/repositories"
	"github.com/vysogota0399/secman/internal/server/storages"
	"github.com/vysogota0399/secman/internal/server/tokens"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

var (
	BuildVersion string = "N/A"
	BuildDate    string = "N/A"
)

func main() {
	fx.New(
		fx.Supply(
			fx.Annotate(BuildVersion, fx.ResultTags(`name:"build_version"`)),
			fx.Annotate(BuildDate, fx.ResultTags(`name:"build_date"`)),
		),
		CreateApp(),
	).Run()
}

func CreateApp() fx.Option {
	return fx.Options(
		fx.Provide(
			config.NewConfig,
			logging.MustZapLogger,
			fx.Annotate(config.NewConfig, fx.As(new(logging.LogLevelFetcher))),

			// core
			fx.Annotate(server.NewCore, fx.ParamTags(`name:"build_version"`, `name:"build_date"`)),
			fx.Annotate(server.NewCoreRepository, fx.ParamTags(`name:"unsealed_barrier"`), fx.As(new(server.ICoreRepository))),
			fx.Annotate(storages.NewStorage,
				fx.As(new(server.IStorage)),
			),
			fx.Annotate(server.NewLogicalRouter, fx.ParamTags(`group:"backends"`), fx.As(new(server.ILogicalRouter))),
			fx.Annotate(bariers.NewUnsealedBarrier, fx.As(new(server.BarrierStorage)), fx.ResultTags(`name:"unsealed_barrier"`)),
			fx.Annotate(bariers.NewAes256Barier, fx.As(new(server.IBarrier)), fx.As(new(server.BarrierStorage))),
			fx.Annotate(server.NewAuth, fx.As(new(server.IAuth))),
			server.NewKeyring,

			//--> engines
			// blobs
			fx.Annotate(blobs.NewBackend, fx.As(new(server.LogicalBackend)), fx.ResultTags(`group:"backends"`)),
			fx.Annotate(blobs.NewRepository),
			fx.Annotate(blobs.NewMetadataRepository, fx.ParamTags(`name:"unsealed_barrier"`)),
			fx.Annotate(blobs.NewMinio, fx.As(new(blobs.S3))),

			// logopass
			logopass.NewLogopass,
			fx.Annotate(logopass.NewBackend, fx.As(new(server.LogicalBackend)), fx.ResultTags(`group:"backends"`)),
			fx.Annotate(logopass_repositories.NewParamsRepository, fx.As(new(logopass.ParamsRepository))),

			// kv
			fx.Annotate(kv.NewBackend, fx.As(new(server.LogicalBackend)), fx.ResultTags(`group:"backends"`)),
			fx.Annotate(kv.NewRepository),
			fx.Annotate(kv.NewMetadataRepository, fx.ParamTags(`name:"unsealed_barrier"`)),

			// pci_dss
			fx.Annotate(pcidss.NewBackend, fx.As(new(server.LogicalBackend)), fx.ResultTags(`group:"backends"`)),
			fx.Annotate(pcidss.NewRepository),
			fx.Annotate(pcidss.NewMetadataRepository, fx.ParamTags(`name:"unsealed_barrier"`)),

			//<-- engines

			// iam
			fx.Annotate(iam_repositories.NewSessions, fx.As(new(iam.SessionsRepository))),
			fx.Annotate(iam_repositories.NewUsers, fx.As(new(iam.UsersRepository))),
			fx.Annotate(iam.NewCore,
				fx.As(new(logopass.IamAdapter)),
			),

			// tokens
			fx.Annotate(tokens.NewRootToken, fx.As(new(server.IRootTokens))),
			fx.Annotate(tokens.NewTokensRepository, fx.ParamTags(`name:"unsealed_barrier"`)),

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
		zap.Int("pid", os.Getpid()),
	)
}

func runServer(server *http.Server) {}
