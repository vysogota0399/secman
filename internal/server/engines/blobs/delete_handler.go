package blobs

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) deleteHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	token := params.Params["token"]

	blobKey, ok, err := b.repo.GetBlobKeyOk(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob %w", err)
	}

	if !ok {
		return &server.LogicalResponse{
			Status: http.StatusNotFound,
			Message: gin.H{
				"error": "blob not found",
			},
		}, nil
	}

	if err := b.repo.Delete(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to delete blob %w", err)
	}

	if err := b.metadata.Delete(ctx, token); err != nil {
		return nil, fmt.Errorf("failed to delete metadata %w", err)
	}

	if err := b.s3.Delete(ctx, blobKey); err != nil {
		return nil, fmt.Errorf("failed to delete blob %w", err)
	}

	return &server.LogicalResponse{
		Status: http.StatusOK,
	}, nil
}
