package pci_dss

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) ShowPanHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["pan_token"]

	pan, ok, err := b.repo.ValueOk(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get pan: %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "pan not found"},
		}, nil
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": pan},
	}, nil
}
