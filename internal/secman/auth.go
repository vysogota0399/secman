package secman

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
)

type authPath string

type AuthorizeBackend interface {
	LogicalBackend
	Authorize(c *gin.Context) (bool, error)
}

type IAuth interface {
	PostUnseal(ctx context.Context, router ILogicalRouter) error
	EnableEngine(ctx context.Context, engine LogicalBackend) error
	Authorize(c *gin.Context) error
}

var _ IAuth = (*Auth)(nil)

type Auth struct {
	Engines          []authPath `json:"engines"`
	engineCollection []AuthorizeBackend
	coreRepository   ICoreRepository
	authMtx          sync.RWMutex
	lg               *logging.ZapLogger
}

func NewAuth(coreRepository ICoreRepository, lg *logging.ZapLogger) *Auth {
	return &Auth{
		Engines:          []authPath{},
		engineCollection: []AuthorizeBackend{},
		coreRepository:   coreRepository,
		authMtx:          sync.RWMutex{},
		lg:               lg,
	}
}

func (a *Auth) PostUnseal(ctx context.Context, router ILogicalRouter) error {
	authConfig, err := a.coreRepository.GetCoreAuthConfig(ctx)
	if err != nil && !errors.Is(err, ErrEntryNotFound) {
		return fmt.Errorf("auth: failed to get core config: %w", err)
	}

	// if core config is not set, initialize it and return
	if authConfig == nil {
		authConfig = &Auth{
			Engines: []authPath{},
		}

		err = a.coreRepository.UpdateCoreAuthConfig(ctx, authConfig)
		if err != nil {
			return fmt.Errorf("auth: failed to update core config: %w", err)
		}

		return nil
	}

	a.Engines = authConfig.Engines
	a.engineCollection = make([]AuthorizeBackend, 0, len(a.Engines))

	for _, engine := range a.Engines {
		e, err := router.Resolve(string(engine))
		if err != nil {
			return fmt.Errorf("auth: failed to resolve engine %s: %w", engine, err)
		}

		authBackend, ok := e.(AuthorizeBackend)
		if !ok {
			return nil
		}

		a.engineCollection = append(a.engineCollection, authBackend)
	}

	return nil
}

func (a *Auth) EnableEngine(ctx context.Context, engine LogicalBackend) error {
	a.authMtx.Lock()
	defer a.authMtx.Unlock()

	a.Engines = append(a.Engines, authPath(engine.RootPath()))

	err := a.coreRepository.UpdateCoreAuthConfig(ctx, a)
	if err != nil {
		return fmt.Errorf("auth: failed to update core config: %w", err)
	}

	authBackend, ok := engine.(AuthorizeBackend)
	if !ok {
		return fmt.Errorf("auth: engine %s is not an AuthorizeBackend", engine.RootPath())
	}

	a.engineCollection = append(a.engineCollection, authBackend)

	return nil
}

var ErrUnauthorized = errors.New("unauthorized")

func (a *Auth) Authorize(c *gin.Context) error {
	for _, engine := range a.engineCollection {
		ok, err := engine.Authorize(c)
		if err != nil {
			return err
		}

		if ok {
			return nil
		}
	}

	return ErrUnauthorized
}
