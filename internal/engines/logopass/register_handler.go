package logopass

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
	"go.uber.org/zap"
)

func (b *Backend) registerHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	body, ok := params.Body.(*RegisterPathBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	user := iam_repositories.User{
		Login:    body.Login,
		Password: body.Password,
	}

	if err := b.logopass.Register(ctx, user); err != nil {
		if errors.Is(err, ErrUserAlreadyExists) {
			return &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "user with this login already exists"},
			}, nil
		}

		b.lg.ErrorCtx(ctx, "registration_handler: registration failed", zap.Error(err))

		return nil, err
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
