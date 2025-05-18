package services

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
)

type IamAdapter interface {
	Register(ctx context.Context, user iam_repositories.User) error
	Login(ctx context.Context, session iam_repositories.Session) error
}

type CreateRootService struct {
	iam IamAdapter
}

func NewCreateRootService(iam IamAdapter) *CreateRootService {
	return &CreateRootService{iam: iam}
}

func (s *CreateRootService) Call(ctx context.Context) (string, error) {
	root := iam_repositories.User{
		Login:     "root",
		CreatedAt: time.Now(),
	}

	if err := s.iam.Register(ctx, root); err != nil {
		return "", fmt.Errorf("create_root: create root user error: %w", err)
	}

	session := iam_repositories.Session{
		UUID:      s.random(),
		Sub:       root.Login,
		CreatedAt: time.Now(),
		// never expire
		ExpiredAt: time.Time{},
	}

	if err := s.iam.Login(ctx, session); err != nil {
		return "", fmt.Errorf("create_root: create root session error: %w", err)
	}

	return session.UUID, nil
}

func (c *CreateRootService) random() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	pass := make([]byte, 32)

	_, err := rnd.Read(pass)
	if err != nil {
		return ""
	}

	return string(pass)
}
