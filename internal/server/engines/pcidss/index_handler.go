package pcidss

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) indexHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	entries, err := b.repo.List(ctx, "/")
	if err != nil {
		return nil, err
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": entries},
	}, nil
}
