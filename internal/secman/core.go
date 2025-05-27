package secman

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type PhysicalEntry struct {
	Value []byte `json:"value"`
	Key   string `json:"key"`
}

// IStorage is an interface that defines the methods for a storage
// - Get is a method that gets an entry from the storage
// - Update is a method that updates an entry in the storage
// - Delete is a method that deletes an entry from the storage
type IStorage interface {
	Get(ctx context.Context, path string) (PhysicalEntry, error)
	Update(ctx context.Context, path string, value PhysicalEntry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, path string) ([]PhysicalEntry, error)
}

var ErrEntryNotFound = errors.New("entry not found")

type IRootTokens interface {
	Gen(ctx context.Context, path string) (string, error)
	Compare(ctx context.Context, path string, token string) error
}

type Core struct {
	IsInitialized *atomic.Bool
	sealedMtx     sync.RWMutex
	IsSealed      *atomic.Bool
	initMtx       sync.RWMutex
	Log           *logging.ZapLogger
	Barrier       IBarrier
	Parent        *Core
	Config        *config.Config
	RootTokens    IRootTokens
	Router        ILogicalRouter
	Auth          IAuth
}

func NewCore(
	barrier IBarrier,
	lc fx.Lifecycle,
	log *logging.ZapLogger,
	config *config.Config,
	coreRepository ICoreRepository,
	rootTokens IRootTokens,
	router ILogicalRouter,
	auth IAuth,
) *Core {
	core := &Core{
		Log:           log,
		sealedMtx:     sync.RWMutex{},
		IsSealed:      &atomic.Bool{},
		IsInitialized: &atomic.Bool{},
		Config:        config,
		Barrier:       barrier,
		RootTokens:    rootTokens,
		Router:        router,
		Auth:          auth,
	}

	lc.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				log.InfoCtx(ctx, "starting core", zap.Any("config", core.Config))

				{
					initialized, err := coreRepository.IsCoreInitialized(context.Background())
					if err != nil {
						return err
					}

					core.IsInitialized.Store(initialized)
				}

				core.IsSealed.Store(true)

				log.InfoCtx(ctx, "core started")
				return nil
			},
		},
	)

	return core
}

func (c *Core) Init(coreRepository ICoreRepository) error {
	c.initMtx.Lock()
	defer c.initMtx.Unlock()

	if c.IsInitialized.Load() {
		return errors.New("core: already initialized")
	}

	if err := coreRepository.SetCoreInitialized(context.Background(), true); err != nil {
		return err
	}

	c.IsInitialized.Store(true)

	return nil
}

func (c *Core) Unseal(ctx context.Context, key []byte) error {
	c.sealedMtx.Lock()
	defer c.sealedMtx.Unlock()

	unsealed, err := c.Barrier.Unseal(ctx, key)
	if err != nil {
		return err
	}

	if !unsealed {
		return nil
	}

	// mount enabled backend engines
	if err := c.Router.PostUnsealEngines(ctx); err != nil {
		return fmt.Errorf("core: unseal failed when mounting enabled engines: %w", err)
	}

	// mount auth
	if err := c.Auth.PostUnseal(ctx, c.Router); err != nil {
		return fmt.Errorf("core: unseal failed when mounting auth engines: %w", err)
	}

	c.IsSealed.Store(false)

	return nil
}
