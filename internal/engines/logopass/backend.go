package logopass

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/config"
	"github.com/vysogota0399/secman/internal/secman/repositories"
)

var (
	PATH = "/auth/logopass"
)

type SessionsRepository interface {
	Create(ctx context.Context, session *repositories.Session) error
	Get(ctx context.Context, sessionID string) (repositories.Session, error)
}

type UsersRepository interface {
	Get(ctx context.Context, userID string) (repositories.User, error)
}

var _ SessionsRepository = &repositories.Sessions{}
var _ UsersRepository = &repositories.Users{}
var _ secman.Backend = &Backend{}

type Engine struct {
	lg       *logging.ZapLogger
	sessRep  SessionsRepository
	usersRep UsersRepository
}

func NewEngine(
	lg *logging.ZapLogger,
	sessRep SessionsRepository,
	usersRep UsersRepository,
) *Engine {
	return &Engine{lg: lg, sessRep: sessRep, usersRep: usersRep}
}

func (e *Engine) Factory(core *secman.Core) secman.Backend {
	return &Backend{core: core, engine: e}
}

func Factory(
	core *secman.Core,
) *Backend {
	return &Backend{
		core: core,
	}
}

type Backend struct {
	core   *secman.Core
	engine *Engine
}

func (b *Backend) RootPath() string {
	return "auth/logopass"
}

func (b *Backend) Help() string {
	return "Logopass authentication backend, uses login and password to authenticate"
}

func (b *Backend) Enable() error {
	return nil
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
			Path:        PATH + "/logout",
			Method:      http.MethodDelete,
			Handler:     nil,
			Description: "Logout from the system",
			Fields:      []secman.Field{},
		},
		{
			Path:        PATH + "/register",
			Method:      http.MethodPost,
			Handler:     nil,
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
	}
}

func NewAuth(
	config *config.Config,
	lg *logging.ZapLogger,
	sessRep SessionsRepository,
	usersRep UsersRepository,
) (*JWT, error) {
	cfg := config.Auth
	authType, ok := cfg["type"].(string)
	if !ok {
		return nil, fmt.Errorf("initialize auth failed: type cast error for auth type - got %T expected string", cfg["type"])
	}

	switch authType {
	case "jwt":
		jwtCfg, err := NewJWTConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("initialize jwt auth failed: %w", err)
		}

		return NewJWT(
			jwtCfg,
			sessRep,
			usersRep,
			lg,
		), nil
	default:
		return nil, fmt.Errorf("auth type %s not found", authType)
	}
}
