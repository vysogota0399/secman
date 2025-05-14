package logopass

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) getParamsHandler(ctx *gin.Context) (*secman.LogicalResponse, error) {
	params := b.getParams()

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: params,
	}, nil
}

func (b *Backend) getParams() *repositories.Params {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	return b.params
}
