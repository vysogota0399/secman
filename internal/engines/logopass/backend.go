package logopass

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
	"go.uber.org/zap"
)

var (
	PATH = "/auth/logopass"
)

type ParamsRepository interface {
	IsExist(ctx context.Context) (bool, error)
	Get(ctx context.Context) (*repositories.Params, error)
	Update(ctx context.Context, params *repositories.Params) error
}

type IamAdapter interface {
	Login(ctx context.Context, path string, backend *Backend) (string, error)
	Authorize(ctx context.Context, token string, backend *Backend) error
	Register(ctx context.Context, user iam_repositories.User) error
}

var (
	_ ParamsRepository = &repositories.ParamsRepository{}
	_ secman.Backend   = &Backend{}
	_ secman.Engine    = &Engine{}
	_ IamAdapter       = &Logopass{}
)

type Engine struct {
	lg        *logging.ZapLogger
	paramsRep ParamsRepository
	logopass  IamAdapter
}

func NewEngine(
	lg *logging.ZapLogger,
	b secman.IBarrier,
	logopass IamAdapter,
) *Engine {
	paramsRep := repositories.NewParamsRepository(lg, b, PATH)
	return &Engine{
		lg:        lg,
		paramsRep: paramsRep,
		logopass:  logopass,
	}
}

func (e *Engine) Factory(core *secman.Core) secman.Backend {
	exist := &atomic.Bool{}
	exist.Store(false)

	return &Backend{
		core:   core,
		engine: e,
		beMtx:  sync.RWMutex{},
		exist:  exist,
	}
}

func (e *Engine) Name() string {
	return "logopass"
}

type Backend struct {
	core   *secman.Core
	engine *Engine
	beMtx  sync.RWMutex
	exist  *atomic.Bool
	params *repositories.Params
}

func (b *Backend) RootPath() string {
	return PATH
}

func (b *Backend) Help() string {
	return "Logopass authentication backend, uses login and password to authenticate"
}

func (b *Backend) Paths() []*secman.Path {
	return []*secman.Path{
		{
			Path:        PATH + "/login",
			Method:      http.MethodPost,
			Handler:     nil,
			Description: "Login to the system by login and password",
			Fields: []secman.Field{
				{
					Name:        "login",
					Description: "Login",
					Required:    true,
				},
				{
					Name:        "password",
					Description: "Password",
					Required:    true,
				},
			},
		},
		{
			Path:        PATH + "/register",
			Method:      http.MethodPost,
			Handler:     b.registerHandler,
			Description: "Register a new user",
			Fields: []secman.Field{
				{
					Name:        "login",
					Description: "Login",
					Required:    true,
				},
				{
					Name:        "password",
					Description: "Password",
					Required:    true,
				},
			},
		},
		{
			Path:        PATH + "/params",
			Method:      http.MethodGet,
			Handler:     b.getParamsHandler,
			Description: "Get the params",
		},
		{
			Path:        PATH + "/params",
			Method:      http.MethodPut,
			Handler:     nil,
			Description: "Set the params",
			Fields: []secman.Field{
				{
					Name:        "token_ttl",
					Description: "Token TTL",
				},
				{
					Name:        "secret_key",
					Description: "Secret Key",
				},
			},
		},
	}
}

func (b *Backend) Enable(ctx context.Context, req *secman.LogicalRequest) (*secman.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	if b.exist.Load() {
		return &secman.LogicalResponse{
			Status:  http.StatusNotModified,
			Message: "logopass: already enabled",
		}, nil
	}

	params := &repositories.Params{}
	b.params = params

	if err := req.ShouldBindJSON(params); err != nil {
		b.engine.lg.DebugCtx(ctx, "logopass: enable failed error when binding json", zap.Error(err))
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "body is invalid or empty",
		}, nil
	}

	if params.SecretKey == "" {
		params.SecretKey = generateSecretKey()
	}

	if err := b.engine.paramsRep.Update(ctx, params); err != nil {
		return nil, fmt.Errorf("logopass: enable failed error when updating params %w", err)
	}

	b.exist.Store(true)

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: "logopass enabled",
	}, nil
}

// Mount mounts the logopass engine. Its check if the engine is enabled, then loads itself params to memory.
func (b *Backend) Mount(ctx context.Context) error {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	ok, err := b.engine.paramsRep.IsExist(ctx)
	if err != nil {
		return fmt.Errorf("logopass: check engine enabled failed error: %w", err)
	}

	if !ok {
		return fmt.Errorf("logopass: engine is not enabled")
	}

	params, err := b.engine.paramsRep.Get(ctx)
	if err != nil {
		return fmt.Errorf("logopass: get params failed error: %w", err)
	}

	b.params = params
	b.exist.Store(true)

	return nil
}

func generateSecretKey() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	key := make([]byte, 32)

	_, _ = rnd.Read(key)

	return base64.StdEncoding.EncodeToString(key)
}
