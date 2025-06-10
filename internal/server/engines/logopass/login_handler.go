package logopass

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) LoginHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	body, ok := params.Body.(*LoginPathBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	user, err := b.logopass.Authenticate(ctx, body.Login, body.Password)
	if err != nil {
		return &server.LogicalResponse{
			Status:  http.StatusUnauthorized,
			Message: gin.H{"error": "invalid credentials"},
		}, nil
	}

	token, err := b.logopass.Login(ctx, user, b)
	if err != nil {
		return &server.LogicalResponse{
			Status:  http.StatusInternalServerError,
			Message: gin.H{"error": "failed to login"},
		}, nil
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"token": token},
	}, nil
}
