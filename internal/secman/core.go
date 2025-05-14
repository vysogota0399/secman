package secman

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Entry struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}

type PhysicalEntry struct {
	Value []byte `json:"value"`
}

// IStorage is an interface that defines the methods for a storage
// - Get is a method that gets an entry from the storage
// - Update is a method that updates an entry in the storage
// - Delete is a method that deletes an entry from the storage
type IStorage interface {
	Get(ctx context.Context, path string) (PhysicalEntry, error)
	Update(ctx context.Context, path string, value PhysicalEntry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
}

// IBarrier is an interface that defines the methods for a barrier. When the barrier is sealed, the storage is not accessible.
// To unseal the barrier, the secret key is needed.
// - Unseal is a method that unseals the barrier
type IBarrier interface {
	Get(ctx context.Context, path string) (Entry, error)
	GetOk(ctx context.Context, path string) (Entry, bool, error)
	Update(ctx context.Context, path string, value Entry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
	Unseal(ctx context.Context, key []byte) error
}

type Core struct {
	isSealed       bool
	sealedMtx      sync.RWMutex
	initialized    bool
	initMtx        sync.RWMutex
	Log            *logging.ZapLogger
	LogicalStorage IBarrier
	Parent         *Core
	Config         *config.Config
	Router         *LogicalRouter
	coreRepository *CoreRepository
}

func NewCore(
	engines []Engine,
	lc fx.Lifecycle,
	log *logging.ZapLogger,
	config *config.Config,
	barrier IBarrier,
	storage IStorage,
	coreRepository *CoreRepository,
) (*Core, error) {
	core := &Core{
		Log:            log,
		sealedMtx:      sync.RWMutex{},
		isSealed:       true,
		Config:         config,
		LogicalStorage: barrier,
		coreRepository: coreRepository,
	}

	{
		initialized, err := core.coreRepository.IsCoreInitialized(context.Background())
		if err != nil {
			return nil, err
		}

		core.initialized = initialized
	}
	{
		enginesMap := NewEnginesMap(core, engines...)
		log.InfoCtx(context.Background(), "initializing engines")
		r, err := NewLogicalRouter(enginesMap, core)
		if err != nil {
			return nil, err
		}
		log.InfoCtx(context.Background(), "initializing engines finished")
		core.Router = r
	}

	lc.Append(
		fx.Hook{
			OnStart: func(ctx context.Context) error {
				log.InfoCtx(ctx, "starting core", zap.Any("config", core.Config))
				return nil
			},
		},
	)

	return core, nil
}

func (c *Core) Init() error {
	c.initMtx.Lock()
	defer c.initMtx.Unlock()

	if c.initialized {
		return errors.New("core: already initialized")
	}

	if err := c.coreRepository.SetCoreInitialized(context.Background(), true); err != nil {
		return err
	}

	c.initialized = true

	return nil
}

func (c *Core) IsInitialized() bool {
	c.initMtx.RLock()
	defer c.initMtx.RUnlock()

	return c.initialized
}

func (c *Core) IsSealed() bool {
	c.sealedMtx.RLock()
	defer c.sealedMtx.RUnlock()

	return c.isSealed
}

func (c *Core) Unseal(ctx context.Context, key []byte) error {
	c.sealedMtx.Lock()
	defer c.sealedMtx.Unlock()

	if err := c.LogicalStorage.Unseal(ctx, key); err != nil {
		return err
	}

	c.isSealed = false

	return nil
}
