package auth

import (
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/repositories"
)

func NewAuth(
	authType string,
	config secman.Config,
	lg *logging.ZapLogger,
	sessRep *repositories.Sessions,
	usersRep *repositories.Users,
) (secman.IAuth, error) {
	cfg := config.Auth
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
