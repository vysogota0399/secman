package blobs

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) showBlob(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	token := params.Params["token"]

	blobKey, ok, err := b.repo.GetBlobKeyOk(ctx, token)
	if err != nil {
		return nil, err
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "blob not found"},
		}, nil
	}

	metadata, err := b.metadata.Get(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get file's metadata: %w", err)
	}

	if metadata["file_name"] == "" {
		return nil, fmt.Errorf("failed to get file's metadata, name is empty")
	}

	blob, err := b.s3.Get(ctx, blobKey)

	if err != nil {
		return nil, fmt.Errorf("failed to get blob %w", err)
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"blob": blob},
		Headers: map[string]string{
			"Content-Type":        "application/octet-stream",
			"Content-Disposition": fmt.Sprintf("attachment; filename=%s", metadata["file_name"]),
			"Content-Length":      strconv.Itoa(int(blob.Size)),
		},
		Reader:      blob.Value,
		ContentSize: blob.Size,
	}, nil
}
