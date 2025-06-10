package kv

import (
	"context"
	"fmt"
	"net/http"

	"maps"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) UpdateMetadataHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	key := params.Params["key"]

	updateMetadata, ok := params.Body.(*MetadataBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, ptr", params.Body)
	}

	entry, ok, err := b.metadata.GetOk(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get key %s metadata: %w", key, err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "key not found", "key": key},
		}, nil
	}

	newKeyMetadata := make(map[string]string, len(entry)+len(updateMetadata.Metadata))
	maps.Copy(newKeyMetadata, entry)
	maps.Copy(newKeyMetadata, updateMetadata.Metadata)

	err = b.metadata.Update(ctx, key, newKeyMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to update key %s metadata: %w", key, err)
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
