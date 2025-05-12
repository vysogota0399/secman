package secman

import (
	"context"
	"sync"

	"github.com/vysogota0399/secman/internal/logging"
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

type IAuth interface {
	Login(ctx context.Context, path string) (string, error)
	Authorize(ctx context.Context, token string) error
	Authenticate(ctx context.Context, login, password string) error
}

type Core struct {
	isSealed  bool
	sealedMtx sync.RWMutex
	Log       *logging.ZapLogger
	Barrier   IBarrier
	Auth      IAuth
	Parent    *Core
}

func NewRootCore(log *logging.ZapLogger, barrier IBarrier, auth IAuth) *Core {
	return &Core{
		Log:       log,
		Barrier:   barrier,
		Auth:      auth,
		sealedMtx: sync.RWMutex{},
		isSealed:  true,
	}
}

func (c *Core) IsSealed() bool {
	c.sealedMtx.RLock()
	defer c.sealedMtx.RUnlock()

	return c.isSealed
}
