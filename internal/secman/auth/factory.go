package auth

import (
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
	"github.com/vysogota0399/secman/internal/secman/repositories"
)

func NewAuth(
	config config.Config,
	lg *logging.ZapLogger,
	sessRep *repositories.Sessions,
	usersRep *repositories.Users,
) (*JWT, error) {
	cfg := config.Auth
	authType, ok := cfg["type"].(string)
	if !ok {
		return nil, fmt.Errorf("type cast error for auth type, got %T expected string", cfg["type"])
	}

	switch authType {
	case "jwt":
		return NewJWT(
			NewJWTConfig(cfg),
			sessRep,
			usersRep,
			lg,
		), nil
	default:
		return nil, fmt.Errorf("auth type %s not found", authType)
	}
}
