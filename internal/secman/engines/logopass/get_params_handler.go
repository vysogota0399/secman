package logopass

import (
	"context"
	"net/http"

	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/engines/logopass/repositories"
)

func (b *Backend) getParamsHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	prms := b.getParams()

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: prms,
	}, nil
}

func (b *Backend) getParams() *repositories.Params {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	return b.params
}
