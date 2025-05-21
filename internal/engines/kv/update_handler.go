package kv

import (
	"fmt"
	"net/http"

	"maps"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) UpdateParamsHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	key := params.Params["key"]

	entry, ok, err := b.repo.ParamsOk(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s params: %w", key, err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "key not found", "key": key},
		}, nil
	}

	updateParams, ok := params.Body.(*ParamsBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, ptr", params.Body)
	}

	newKeyParams := make(map[string]string, len(entry)+len(updateParams.Metadata))
	maps.Copy(newKeyParams, entry)
	maps.Copy(newKeyParams, updateParams.Metadata)

	err = b.repo.UpdateParams(ctx, key, newKeyParams)
	if err != nil {
		return nil, fmt.Errorf("failed to update key %s params: %w", key, err)
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
