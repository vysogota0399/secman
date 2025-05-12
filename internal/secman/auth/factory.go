package auth

import (
	"context"
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
	"github.com/vysogota0399/secman/internal/secman/repositories"
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
