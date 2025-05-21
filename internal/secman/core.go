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
	List(ctx context.Context, path string) ([]Entry, error)
}

var ErrEntryNotFound = errors.New("entry not found")

// IBarrier is an interface that defines the methods for a barrier. When the barrier is sealed, the storage is not accessible.
// To unseal the barrier, the secret key is needed.
// - Unseal is a method that unseals the barrier
type IBarrier interface {
	Get(ctx context.Context, path string) (Entry, error)
	GetOk(ctx context.Context, path string) (Entry, bool, error)
	Update(ctx context.Context, path string, value Entry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
	Unseal(ctx context.Context, key []byte) error
	List(ctx context.Context, path string) ([]Entry, error)
}

type IRootTokens interface {
	Gen(ctx context.Context, path string) (string, error)
	Compare(ctx context.Context, path string, token string) error
}

type Core struct {
	IsInitialized  *atomic.Bool
	sealedMtx      sync.RWMutex
	IsSealed       *atomic.Bool
	initMtx        sync.RWMutex
	Log            *logging.ZapLogger
	LogicalStorage IBarrier
	Parent         *Core
	Config         *config.Config
	RootTokens     IRootTokens
	Router         *LogicalRouter
	Auth           *Auth
}

func NewCore(
	lc fx.Lifecycle,
	log *logging.ZapLogger,
	config *config.Config,
	barrier IBarrier,
	storage IStorage,
	coreRepository *CoreRepository,
	rootTokens IRootTokens,
	router *LogicalRouter,
	auth *Auth,
) *Core {
	core := &Core{
		Log:            log,
		sealedMtx:      sync.RWMutex{},
		IsSealed:       &atomic.Bool{},
		IsInitialized:  &atomic.Bool{},
		Config:         config,
		LogicalStorage: barrier,
		RootTokens:     rootTokens,
		Router:         router,
		Auth:           auth,
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

func (c *Core) Init(coreRepository *CoreRepository) error {
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

	if err := c.LogicalStorage.Unseal(ctx, key); err != nil {
		return err
	}

	// mount enabled engines
	if err := c.Router.PostUnsealEngines(ctx); err != nil {
		return fmt.Errorf("core: unseal failed when mounting enabled engines: %w", err)
	}

	// mount auth engines
	if err := c.Auth.PostUnseal(ctx, c.Router); err != nil {
		return fmt.Errorf("core: unseal failed when mounting auth engines: %w", err)
	}

	c.IsSealed.Store(false)

	return nil
}
