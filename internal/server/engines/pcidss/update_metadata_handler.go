package pcidss

import (
	"context"
	"fmt"
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) UpdateMetadataHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["pan_token"]

	entry, ok, err := b.metadata.GetOk(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get metadata: %w", err)
	}

	if !ok {
		return &server.LogicalResponse{
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

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": newMetadata},
	}, nil
}
