package kv

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) DeleteHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	key := params.Params["key"]

	err := b.repo.Delete(ctx, key)
	if err != nil {
		return nil, err
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
