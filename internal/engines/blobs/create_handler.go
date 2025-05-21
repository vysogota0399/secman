package blobs

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) createHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	metadata, ok := params.Body.(*MetadataBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	data, err := ctx.FormFile("file")
	if err != nil {
		return nil, fmt.Errorf("failed to get file from form data %w", err)
	}

	file, err := data.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open file %w", err)
	}

	metadata.Data["created_at"] = time.Now().Format(time.RFC3339Nano)
	fileUUID := uuid.New().String()

	blob := &Blob{
		Key:   fileUUID,
		Value: file,
		Size:  data.Size,
	}

	if err := b.s3.Create(ctx, blob); err != nil {
		return nil, fmt.Errorf("failed to create blob %w", err)
	}

	if err := b.repo.CreateBlob(ctx, blob.Key); err != nil {
		return nil, fmt.Errorf("failed to save blob secret %w", err)
	}

	if err := b.metadata.Update(ctx, blob.Key, metadata.Data); err != nil {
		return nil, fmt.Errorf("failed to save metadata %w", err)
	}

	return &secman.LogicalResponse{
		Status: http.StatusOK,
		Message: gin.H{
			"key": blob.Key,
		},
	}, nil
}
