package blobs

import (
	"context"
	"net/http"

	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) showMetadataHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	token := params.Params["token"]

	metadata, err := b.metadata.Get(ctx, token)
	if err != nil {
		return nil, err
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: metadata,
	}, nil
}
