package kv

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) DeleteHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	key := params.Params["key"]

	err := b.repo.Delete(ctx, key)
	if err != nil {
		return nil, err
	}

	err = b.metadata.Delete(ctx, key)
	if err != nil {
		return nil, err
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{},
	}, nil
}
