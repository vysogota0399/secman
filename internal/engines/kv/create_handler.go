package kv

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) CreateHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
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
		return nil, fmt.Errorf("key already exists")
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

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
