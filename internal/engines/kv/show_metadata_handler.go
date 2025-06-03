package kv

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) ShowMetadataHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	key := params.Params["key"]

	entry, ok, err := b.metadata.GetOk(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s metadata: %w", key, err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "metadata not found", "key": key},
		}, nil
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": entry},
	}, nil
}
