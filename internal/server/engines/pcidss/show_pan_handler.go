package pcidss

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) ShowPanHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["pan_token"]

	pan, ok, err := b.repo.ValueOk(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get pan: %w", err)
	}

	if !ok {
		return &server.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "pan not found"},
		}, nil
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": pan},
	}, nil
}
