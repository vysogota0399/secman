package kv

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) CreateHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	createParams, ok := params.Body.(*CreateSecretBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	err := b.repo.Create(ctx, createParams.Key, createParams.Value)
	if err != nil {
		return nil, err
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
