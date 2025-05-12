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

type IBarrier interface {
	IStorage
	Unseal(ctx context.Context, key []byte) error
}

type Core struct {
	isSealed   bool
	sealedMtx  sync.RWMutex
	Log        *logging.ZapLogger
	Barrier    IBarrier
	Parent     *Core
	Config     *config.Config
	engines    map[string]Backend
	enginesMtx sync.RWMutex
}

func NewCore(lc fx.Lifecycle, log *logging.ZapLogger, config *config.Config, barrier IBarrier, engines ...Engine) *Core {
	core := &Core{
		Log:       log,
		sealedMtx: sync.RWMutex{},
		isSealed:  true,
		Config:    config,
		Barrier:   barrier,
	}

	lc.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				log.InfoCtx(ctx, "Starting core", zap.Any("config", core.Config))

				core.enginesMtx.Lock()
				for _, engine := range engines {
					backend := engine.Factory(core)
					backend.Enable()

					core.engines[backend.RootPath()] = backend
				}
				core.enginesMtx.Unlock()
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

func (c *Core) Unseal(ctx context.Context, key []byte) error {
	c.sealedMtx.Lock()
	defer c.sealedMtx.Unlock()

	if err := c.Barrier.Unseal(ctx, key); err != nil {
		return err
	}

	c.isSealed = false

	return nil
}
