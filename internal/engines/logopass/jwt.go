package logopass

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/repositories"
	"golang.org/x/crypto/bcrypt"
)

type JWT struct {
	TokenTTL  time.Duration
	SecretKey string
	sessRep   SessionsRepository
	usersRep  UsersRepository
	lg        *logging.ZapLogger
}

type JWTConfig struct {
	TokenTTL  time.Duration
	SecretKey string
}

func NewJWTConfig(cfg map[string]any) (*JWTConfig, error) {
	tokenTTLStr, ok := cfg["token_ttl"].(string)
	if !ok {
		return nil, fmt.Errorf("jwt: token_ttl is not a string")
	}

	tokenTTL, err := time.ParseDuration(tokenTTLStr)
	if err != nil {
		return nil, fmt.Errorf("jwt: invalid token_ttl format: %w", err)
	}

	secretKey, ok := cfg["secret_key"].(string)
	if !ok {
		return nil, fmt.Errorf("jwt: secret_key is not a string")
	}

	return &JWTConfig{
		TokenTTL:  tokenTTL,
		SecretKey: secretKey,
	}, nil
}

func NewJWT(cfg *JWTConfig, sessRep SessionsRepository, usersRep UsersRepository, lg *logging.ZapLogger) *JWT {
	return &JWT{
		TokenTTL:  cfg.TokenTTL,
		SecretKey: cfg.SecretKey,
		sessRep:   sessRep,
		usersRep:  usersRep,
		lg:        lg,
	}
}

func (i *JWT) Authenticate(ctx context.Context, login, password string) error {
	foundUser, err := i.usersRep.Get(ctx, login)
	if err != nil {
		return fmt.Errorf("jwt: user not found %w", err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password)); err != nil {
		return fmt.Errorf("jwt: invalid password %w", err)
	}

	return nil
}

// Login creates a new session and returns the token
func (i *JWT) Login(ctx context.Context, path string) (string, error) {
	session := &repositories.Session{
		Sub:       path,
		ExpiredAt: time.Now().Add(i.TokenTTL),
	}
	if err := i.sessRep.Create(ctx, session); err != nil {
		return "", fmt.Errorf("jwt: create session failed error %w", err)
	}

	return i.buildJWTString(session)
}

// Authorize checks if the token is valid and returns the session
func (i *JWT) Authorize(ctx context.Context, token string) error {
	claims, err := i.decode(token)
	if err != nil {
		return fmt.Errorf("jwt: Authorize error %w", err)
	}

	sess, err := i.sessRep.Get(ctx, claims.Sid)
	if err != nil {
		return fmt.Errorf("jwt: session not found %w", err)
	}

	if time.Now().After(sess.ExpiredAt) {
		return fmt.Errorf("jwt: session expired")
	}

	return nil
}

type Claims struct {
	jwt.RegisteredClaims
	Sid string
}

func (i *JWT) decode(token string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(i.SecretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("jwt: decode token %s failed error %w", token, err)
	}

	return claims, nil
}

func (i *JWT) buildJWTString(session *repositories.Session) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(session.ExpiredAt),
			Subject:   session.Sub,
			IssuedAt:  jwt.NewNumericDate(session.CreatedAt),
		},
		Sid: session.UUID,
	})

	tokenString, err := token.SignedString([]byte(i.SecretKey))
	if err != nil {
		return "", fmt.Errorf("jwt: sign token %s failed error %w", tokenString, err)
	}

	return tokenString, nil
}
