package logopass

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/iam"
	"github.com/vysogota0399/secman/internal/server/iam/repositories"
	"golang.org/x/crypto/bcrypt"
)

type IamAdapter interface {
	Login(ctx context.Context, session repositories.Session) error
	Authorize(ctx context.Context, token string) (repositories.Session, error)
	Register(ctx context.Context, user repositories.User) error
	GetUser(ctx context.Context, login string) (repositories.User, error)
}

type Logopass struct {
	iam IamAdapter
	lg  *logging.ZapLogger
}

func NewLogopass(iam IamAdapter, lg *logging.ZapLogger) *Logopass {
	return &Logopass{
		iam: iam,
		lg:  lg,
	}
}

// Login creates a new session and returns the token
func (lp Logopass) Login(ctx context.Context, user repositories.User, backend *Backend) (string, error) {
	params := backend.getParams()

	ttl := params.TokenTTL
	if ttl == time.Duration(0) {
		ttl = time.Hour * 24 * 365 * 10
	}

	now := time.Now()
	session := repositories.Session{
		UUID:      uuid.New().String(),
		Sub:       user.Path,
		ExpiredAt: now.Add(ttl),
		CreatedAt: now,
		Engine:    "logopass",
	}
	if err := lp.iam.Login(ctx, session); err != nil {
		return "", fmt.Errorf("logopass: create session failed error %w", err)
	}

	return lp.buildJWTString(session, params.SecretKey)
}

// Authorize checks if the token is valid and returns the session
func (lp Logopass) Authorize(ctx context.Context, token string, backend *Backend) error {
	params := backend.getParams()

	claims, err := lp.decode(token, params.SecretKey)
	if err != nil {
		return fmt.Errorf("logopass: Authorize error %w", err)
	}

	sess, err := lp.iam.Authorize(ctx, claims.Sid)
	if err != nil {
		return fmt.Errorf("logopass: session not found %w", err)
	}

	if time.Now().After(sess.ExpiredAt) {
		return fmt.Errorf("logopass: session expired")
	}

	return nil
}

func (lp Logopass) Authenticate(ctx context.Context, login, password string) (repositories.User, error) {
	user, err := lp.iam.GetUser(ctx, login)
	if err != nil {
		if errors.Is(err, server.ErrEntryNotFound) {
			return repositories.User{}, fmt.Errorf("logopass: user %s not found", login)
		}

		return repositories.User{}, fmt.Errorf("logopass: fetch user %s failed error %w", login, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return repositories.User{}, fmt.Errorf("logopass: invalid password")
	}

	return user, nil
}

type Claims struct {
	jwt.RegisteredClaims
	Sid string
}

func (lp Logopass) decode(token string, secretKey string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("logopass: decode token %s failed error %w", token, err)
	}

	return claims, nil
}

func (lp Logopass) buildJWTString(session repositories.Session, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(session.ExpiredAt),
			Subject:   session.Sub,
			IssuedAt:  jwt.NewNumericDate(session.CreatedAt),
		},
		Sid: session.UUID,
	})

	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", fmt.Errorf("logopass: sign token %s failed error %w", tokenString, err)
	}

	return tokenString, nil
}

var (
	ErrUserAlreadyExists = errors.New("logopass: user already exists")
)

func (lp Logopass) Register(ctx context.Context, user repositories.User) error {
	if err := lp.iam.Register(ctx, user); err != nil {
		if errors.Is(err, iam.ErrUserAlreadyExists) {
			return errors.Join(ErrUserAlreadyExists, err)
		}

		return fmt.Errorf("logopass: registration failed error: %w", err)
	}

	return nil
}
