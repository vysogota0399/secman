package logopass

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"sync/atomic"

	"github.com/vysogota0399/secman/internal/engines/logopass/repositories"
	logopass_repositories "github.com/vysogota0399/secman/internal/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
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

var (
	_ ParamsRepository        = &repositories.ParamsRepository{}
	_ secman.AuthorizeBackend = &Backend{}
)

type Backend struct {
	beMtx     sync.RWMutex
	exist     *atomic.Bool
	params    *repositories.Params
	lg        *logging.ZapLogger
	paramsRep ParamsRepository
	logopass  *Logopass
	tokenReg  *regexp.Regexp
}

func NewBackend(lg *logging.ZapLogger, logopass *Logopass, barrier secman.IBarrier) *Backend {
	be := &Backend{
		lg:       lg,
		logopass: logopass,
		beMtx:    sync.RWMutex{},
		exist:    &atomic.Bool{},
		params:   &repositories.Params{},
		tokenReg: regexp.MustCompile(`Bearer\s+(\S+)`),
	}

	be.paramsRep = logopass_repositories.NewParamsRepository(lg, barrier, PATH)

	return be
}

func (b *Backend) RootPath() string {
	return PATH
}

func (b *Backend) Help() string {
	return "Logopass authentication backend, uses login and password to authenticate"
}

func (b *Backend) Paths() map[string]map[string]*secman.Path {
	paths := make(map[string]map[string]*secman.Path)

	// Login path
	loginPath := PATH + "/login"
	if _, ok := paths[http.MethodPost]; !ok {
		paths[http.MethodPost] = make(map[string]*secman.Path)
	}
	paths[http.MethodPost][loginPath] = &secman.Path{
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
		Handler:  b.LoginHandler,
		SkipAuth: true,
	}

	// Register path
	registerPath := PATH + "/register"
	if _, ok := paths[http.MethodPost]; !ok {
		paths[http.MethodPost] = make(map[string]*secman.Path)
	}
	paths[http.MethodPost][registerPath] = &secman.Path{
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
		SkipAuth: true,
	}

	// Get params path
	paramsPath := PATH + "/"
	if _, ok := paths[http.MethodGet]; !ok {
		paths[http.MethodGet] = make(map[string]*secman.Path)
	}
	paths[http.MethodGet][paramsPath] = &secman.Path{
		Handler:     b.getParamsHandler,
		Description: "Get the params",
	}

	// Set params path
	if _, ok := paths[http.MethodPut]; !ok {
		paths[http.MethodPut] = make(map[string]*secman.Path)
	}
	paths[http.MethodPut][paramsPath] = &secman.Path{
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
	}

	return paths
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
		b.lg.DebugCtx(ctx, "logopass: enable failed error when binding json", zap.Error(err))
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "body is invalid or empty",
		}, nil
	}

	if params.SecretKey == "" {
		params.SecretKey = generateSecretKey()
	}

	if err := b.paramsRep.Update(ctx, params); err != nil {
		return nil, fmt.Errorf("logopass: enable failed error when updating params %w", err)
	}

	b.exist.Store(true)

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: "logopass enabled",
	}, nil
}

// PostUnseal mounts the logopass engine. Its check if the engine is enabled, then loads itself params to memory.
func (b *Backend) PostUnseal(ctx context.Context) error {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	ok, err := b.paramsRep.IsExist(ctx)
	if err != nil {
		return fmt.Errorf("logopass: check engine enabled failed error: %w", err)
	}

	if !ok {
		return fmt.Errorf("logopass: post unseal failed error: %w", secman.ErrEngineIsNotEnabled)
	}

	params, err := b.paramsRep.Get(ctx)
	if err != nil {
		return fmt.Errorf("logopass: get params failed error: %w", err)
	}

	b.params = params
	b.exist.Store(true)

	return nil
}

func generateSecretKey() string {
	rnd := rand.Reader

	token := make([]byte, 32)
	if _, err := rnd.Read(token); err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(token)
}
