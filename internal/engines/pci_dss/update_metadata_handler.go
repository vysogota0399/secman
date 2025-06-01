package pci_dss

import (
	"context"
	"fmt"
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) UpdateMetadataHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["card_token"]

	entry, ok, err := b.metadata.GetOk(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "metadata not found"},
		}, nil
	}

	updateMetadata, ok := params.Body.(*MetadataBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, ptr", params.Body)
	}

	newMetadata := make(map[string]string, len(entry)+len(updateMetadata.Metadata))
	maps.Copy(newMetadata, entry)
	maps.Copy(newMetadata, updateMetadata.Metadata)

	err = b.metadata.Update(ctx, cardToken, newMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to update metadata: %w", err)
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": newMetadata},
	}, nil
}
