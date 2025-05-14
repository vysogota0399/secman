package logopass

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
	"go.uber.org/zap"
)

type RegisterRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (b *Backend) registerHandler(ctx *gin.Context) (*secman.LogicalResponse, error) {
	var req RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "invalid request, expected login and password",
		}, nil
	}

	user := iam_repositories.User{
		Login:    req.Login,
		Password: req.Password,
	}

	if err := b.engine.logopass.Register(ctx, user); err != nil {
		b.engine.lg.ErrorCtx(ctx, "registration_handler: registration failed", zap.Error(err))

		if errors.Is(err, ErrUserAlreadyExists) {
			return &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: "user with this login already exists",
			}, nil
		}

		return nil, err
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: "registration successful",
	}, nil
}
