package blobs

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) showMetadataHandler(c *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	token := params.Params["token"]

	metadata, err := b.metadata.Get(c.Request.Context(), token)
	if err != nil {
		return nil, err
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: metadata,
	}, nil
}
