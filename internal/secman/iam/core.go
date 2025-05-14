package iam

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/iam/repositories"
	"golang.org/x/crypto/bcrypt"
)

type SessionsRepository interface {
	Create(ctx context.Context, session *repositories.Session) error
	Get(ctx context.Context, sessionID string) (repositories.Session, error)
}

type UsersRepository interface {
	Get(ctx context.Context, userID string) (repositories.User, error)
	Update(ctx context.Context, user *repositories.User) error
	GetOk(ctx context.Context, login string) (repositories.User, bool, error)
}

var (
	_ SessionsRepository = &repositories.Sessions{}
	_ UsersRepository    = &repositories.Users{}
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
)

type Core struct {
	lg            *logging.ZapLogger
	sessRep       SessionsRepository
	usersRep      UsersRepository
	registrateMtx sync.Mutex
}

func NewCore(lg *logging.ZapLogger, sessRep SessionsRepository, usersRep UsersRepository) *Core {
	return &Core{lg: lg, sessRep: sessRep, usersRep: usersRep}
}

func (c *Core) Authenticate(ctx context.Context, login, password string) error {
	foundUser, err := c.usersRep.Get(ctx, login)
	if err != nil {
		return fmt.Errorf("user %s not found %w", login, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(password)); err != nil {
		return fmt.Errorf("invalid password for user %s %w", login, err)
	}

	return nil
}

func (c *Core) Authorize(ctx context.Context, sid string) (repositories.Session, error) {
	return c.sessRep.Get(ctx, sid)
}

func (c *Core) Login(ctx context.Context, session repositories.Session) error {
	return c.sessRep.Create(ctx, &session)
}

func (c *Core) Register(ctx context.Context, user repositories.User) error {
	c.registrateMtx.Lock()
	defer c.registrateMtx.Unlock()

	user.CreatedAt = time.Now()
	_, ok, err := c.usersRep.GetOk(ctx, user.Login)
	if err != nil {
		return fmt.Errorf("iam/core search user %s error: %w", user.Login, err)
	}

	if ok {
		return fmt.Errorf("iam/core registrate user %s failed, user already exists: %w", user.Login, ErrUserAlreadyExists)
	}

	if createErr := c.usersRep.Update(ctx, &user); createErr != nil {
		return fmt.Errorf("iam/core registrate user %s failed error: %w", user.Login, createErr)
	}

	return nil
}
