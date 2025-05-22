package blobs

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) deleteHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	token := params.Params["token"]

	blobKey, ok, err := b.repo.GetBlobKeyOk(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get blob %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
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

	return &secman.LogicalResponse{
		Status: http.StatusOK,
	}, nil
}
