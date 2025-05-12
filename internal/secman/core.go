package secman

import (
	"context"
	"sync"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Entry struct {
	Uuid  []byte `json:"uuid"`
	Path  []byte `json:"path"`
	Value []byte `json:"value"`
}

type IStorage interface {
	Get(ctx context.Context, path string) (Entry, error)
	Update(ctx context.Context, path string, value Entry) error
	Delete(ctx context.Context, path string) error
}

type IAuth interface {
	Login(ctx context.Context, path string) (string, error)
	Authorize(ctx context.Context, token string) error
	Authenticate(ctx context.Context, login, password string) error
}

type IBarrier interface {
	IStorage
	Unseal(ctx context.Context, key []byte) error
}

type Core struct {
	isSealed  bool
	sealedMtx sync.RWMutex
	Log       *logging.ZapLogger
	Barrier   IBarrier
	Parent    *Core
	Config    *config.Config
	Auth      IAuth
}

func NewCore(lc fx.Lifecycle, log *logging.ZapLogger, config *config.Config) *Core {
	core := &Core{
		Log:       log,
		sealedMtx: sync.RWMutex{},
		isSealed:  true,
		Config:    config,
	}

	lc.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				log.InfoCtx(ctx, "Starting core", zap.Any("config", core.Config))
				return nil
			},
		},
	)

	return core
}

func (c *Core) IsSealed() bool {
	c.sealedMtx.RLock()
	defer c.sealedMtx.RUnlock()

	return c.isSealed
}
