package secman

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/armon/go-radix"
	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap"
)

// EnginesMap is a map of engines. Must be immutable, initialized once for core.
type EnginesMap map[string]Backend

func NewEnginesMap(core *Core, engines ...Engine) EnginesMap {
	em := make(map[string]Backend)
	for _, engine := range engines {
		em[engine.Name()] = engine.Factory(core)
	}

	return em
}

type LogicalRouter struct {
	enginesMap EnginesMap
	engines    *radix.Tree
	mtx        sync.RWMutex
	lg         *logging.ZapLogger
	core       *Core
}

func NewLogicalRouter(enginesMap EnginesMap, core *Core) (*LogicalRouter, error) {
	router := &LogicalRouter{
		enginesMap: enginesMap,
		engines:    radix.New(),
		mtx:        sync.RWMutex{},
		lg:         core.Log,
		core:       core,
	}

	for name, engine := range enginesMap {
		// each engine has params path in the storage
		// if its not true, engine is not enabled
		exist, err := core.coreRepository.IsEngineExist(context.Background(), engine.RootPath()+"/params")
		if err != nil {
			return nil, fmt.Errorf("router: preload engine %s error %w", name, err)
		}

		if exist {
			router.lg.DebugCtx(context.Background(), "preload engine", zap.String("name", name))
			if _, err := router.Register(context.Background(), name); err != nil {
				return nil, fmt.Errorf("router: register engine %s error: %w", name, err)
			}
		}
	}

	return router, nil
}

func (r *LogicalRouter) Register(ctx context.Context, name string) (Backend, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	be, ok := r.enginesMap[name]
	if !ok {
		return nil, fmt.Errorf("router: engine %s: %w", name, ErrEngineNotFound)
	}

	if _, ok := r.engines.Get(be.RootPath()); ok {
		return nil, fmt.Errorf("router: engine %s: %w", name, ErrEngineAlreadyRegistered)
	}

	r.engines.Insert(be.RootPath(), be)

	return be, nil
}

var (
	ErrEngineNotFound          = errors.New("engine not found")
	ErrEngineAlreadyRegistered = errors.New("engine already registered")
)

func (r *LogicalRouter) Resolve(path string) (Backend, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	str, engine, ok := r.engines.LongestPrefix(path)
	if !ok {
		return nil, fmt.Errorf("router: path %s: %w", path, ErrEngineNotFound)
	}

	r.lg.DebugCtx(context.Background(), "resolved engine", zap.String("engine", str))

	be, ok := engine.(Backend)
	if !ok {
		return nil, fmt.Errorf("type cast to backend failed for engine %s %T", str, engine)
	}

	return be, nil
}

func (r *LogicalRouter) Delete(path string) {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	r.engines.Delete(path)
}
