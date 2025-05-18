package logopass

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/iam"
	"github.com/vysogota0399/secman/internal/secman/iam/repositories"
)

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
func (lp Logopass) Login(ctx context.Context, path string, backend *Backend) (string, error) {
	params := backend.getParams()

	now := time.Now()
	session := repositories.Session{
		UUID:      uuid.New().String(),
		Sub:       path,
		ExpiredAt: now.Add(params.TokenTTL),
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
