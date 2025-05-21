package pci_dss

import (
	"fmt"
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) UpdateParamsHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := ctx.Param("card_token")

	entry, ok, err := b.repo.ParamsOk(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get params: %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "params not found"},
		}, nil
	}

	updateParams, ok := params.Body.(*ParamsBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, ptr", params.Body)
	}

	newKeyParams := make(map[string]string, len(entry)+len(updateParams.Metadata))
	maps.Copy(newKeyParams, entry)
	maps.Copy(newKeyParams, updateParams.Metadata)

	err = b.repo.UpdateParams(ctx, cardToken, newKeyParams)
	if err != nil {
		return nil, fmt.Errorf("failed to update params: %w", err)
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"params": newKeyParams},
	}, nil
}
