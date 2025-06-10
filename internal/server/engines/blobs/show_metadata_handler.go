package blobs

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) showMetadataHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	token := params.Params["token"]

	metadata, err := b.metadata.Get(ctx, token)
	if err != nil {
		return nil, err
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": metadata},
	}, nil
}
