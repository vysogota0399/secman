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
	path := b.Paths()[http.MethodPost][b.logicalPath(ctx)]

	var req RegisterRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		return &secman.LogicalResponse{
			Status: http.StatusBadRequest,
			Message: gin.H{
				"error":  "invalid request body",
				"schema": path.Fields,
			},
		}, nil
	}

	user := iam_repositories.User{
		Login:    req.Login,
		Password: req.Password,
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
