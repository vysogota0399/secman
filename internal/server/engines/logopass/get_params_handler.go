package logopass

import (
	"context"
	"net/http"

	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/engines/logopass/repositories"
)

func (b *Backend) getParamsHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	prms := b.getParams()

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: prms,
	}, nil
}

func (b *Backend) getParams() *repositories.Params {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	return b.params
}
