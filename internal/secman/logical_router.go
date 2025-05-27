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

type ILogicalRouter interface {
	Register(ctx context.Context, engine LogicalBackend) error
	Resolve(path string) (LogicalBackend, error)
	PostUnsealEngines(ctx context.Context) error
	EnableEngine(ctx context.Context, engine LogicalBackend, req *LogicalRequest) (*LogicalResponse, error)
}

var _ ILogicalRouter = (*LogicalRouter)(nil)

type LogicalRouter struct {
	engines *radix.Tree
	mtx     sync.RWMutex
	lg      *logging.ZapLogger
}

func NewLogicalRouter(engines []LogicalBackend, coreRepository ICoreRepository, lg *logging.ZapLogger) (*LogicalRouter, error) {
	lg.InfoCtx(context.Background(), "initializing logical router start", zap.Int("engines_count", len(engines)))
	defer lg.InfoCtx(context.Background(), "initializing logical router finished")

	router := &LogicalRouter{
		engines: radix.New(),
		mtx:     sync.RWMutex{},
		lg:      lg,
	}

	for _, engine := range engines {

		router.lg.DebugCtx(context.Background(), "preload engine", zap.String("path", engine.RootPath()))
		if err := router.Register(context.Background(), engine); err != nil {
			return nil, fmt.Errorf("router: register engine %s error: %w", engine.RootPath(), err)
		}
	}

	return router, nil
}

// Register registers the engine to the router
func (r *LogicalRouter) Register(ctx context.Context, engine LogicalBackend) error {
	r.mtx.Lock()
	defer r.mtx.Unlock()

	if _, _, ok := r.engines.LongestPrefix(engine.RootPath()); ok {
		return fmt.Errorf("router: engine %s: %w", engine.RootPath(), ErrEngineAlreadyRegistered)
	}

	r.engines.Insert(engine.RootPath(), engine)

	return nil
}

var (
	ErrEngineNotFound          = errors.New("engine not found")
	ErrEngineAlreadyRegistered = errors.New("engine already registered")
)

// Resolve resolves the engine from the path
func (r *LogicalRouter) Resolve(path string) (LogicalBackend, error) {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	str, engine, ok := r.engines.LongestPrefix(path)
	if !ok {
		return nil, fmt.Errorf("router: path %s: %w", path, ErrEngineNotFound)
	}

	be, ok := engine.(LogicalBackend)
	if !ok {
		return nil, fmt.Errorf("type cast to backend failed for engine %s %T", str, engine)
	}

	return be, nil
}

// PostUnsealEngines initializes the backend router for all engines and post unseal them
func (r *LogicalRouter) PostUnsealEngines(ctx context.Context) error {
	r.mtx.RLock()
	defer r.mtx.RUnlock()

	engines := r.engines.ToMap()

	for _, engine := range engines {
		be, ok := engine.(LogicalBackend)
		if !ok {
			return fmt.Errorf("router: type cast backend to engine failed %T", engine)
		}

		if err := r.initBackendRouter(be); err != nil {
			return fmt.Errorf("router: init backend router failed error: %w", err)
		}

		if err := be.PostUnseal(ctx); err != nil {
			if errors.Is(err, ErrEngineIsNotEnabled) {
				r.lg.DebugCtx(ctx, "router: engine is not enabled, skip", zap.String("engine", be.RootPath()))
				continue
			}

			return fmt.Errorf("router: post unseal engine %s error: %w", be.RootPath(), err)
		}
	}

	return nil
}

// EnableEngine enables the engine and initializes the backend router
func (r *LogicalRouter) EnableEngine(ctx context.Context, engine LogicalBackend, req *LogicalRequest) (*LogicalResponse, error) {
	if err := r.initBackendRouter(engine); err != nil {
		return nil, fmt.Errorf("router: init backend router failed error: %w", err)
	}

	resp, err := engine.Enable(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("router: enable engine %s error: %w", engine.RootPath(), err)
	}

	return resp, nil
}

func (r *LogicalRouter) initBackendRouter(engine LogicalBackend) error {
	router, err := NewBackendRouter(engine)
	if err != nil {
		return fmt.Errorf("router: init backend router failed error: %w", err)
	}

	engine.SetRouter(router)
	return nil
}
