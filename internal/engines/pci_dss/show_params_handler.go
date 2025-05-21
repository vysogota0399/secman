package pci_dss

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) ShowParamsHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := ctx.Param("card_token")

	_, ok, err := b.repo.ParamsOk(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "params not found"},
		}, nil
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"params": params},
	}, nil
}
