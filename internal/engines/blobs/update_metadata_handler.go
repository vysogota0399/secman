package blobs

import (
	"fmt"
	"maps"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) updateMetadataHandler(c *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	token := params.Params["token"]
	metadata, ok := params.Body.(*MetadataBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, ptr", params.Body)
	}

	entry, ok, err := b.metadata.GetOk(c.Request.Context(), token)
	if err != nil {
		return nil, err
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "metadata not found"},
		}, nil
	}

	newMetadata := make(map[string]string, len(entry)+len(metadata.Metadata))
	maps.Copy(newMetadata, entry)
	maps.Copy(newMetadata, metadata.Metadata)

	err = b.metadata.Update(c.Request.Context(), token, newMetadata)
	if err != nil {
		return nil, fmt.Errorf("failed to update metadata %+v for token %s: %w", newMetadata, token, err)
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: newMetadata,
	}, nil
}
