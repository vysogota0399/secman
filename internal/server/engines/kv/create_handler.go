package kv

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) CreateHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	createParams, ok := params.Body.(*CreateSecretBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	_, ok, err := b.metadata.GetOk(ctx, createParams.Key)
	if err != nil {
		return nil, err
	}

	if ok {
		return &server.LogicalResponse{
			Status:  http.StatusConflict,
			Message: gin.H{"error": "key already exists"},
		}, nil
	}

	if err := b.repo.Create(ctx, createParams.Key, createParams.Value); err != nil {
		return nil, err
	}

	metadata := map[string]string{
		"created_at": time.Now().Format(time.RFC3339),
	}

	if err := b.metadata.Update(ctx, createParams.Key, metadata); err != nil {
		return nil, err
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
