package pci_dss

import (
	"context"
	"fmt"
	"net/http"

	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) DeleteHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	cardToken := params.Params["card_token"]

	paths, err := b.repo.List(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list paths: %w", err)
	}

	for _, path := range paths {
		if err := b.repo.Delete(ctx, path.Key); err != nil {
			return nil, fmt.Errorf("failed to delete path: %w", err)
		}
	}

	return &secman.LogicalResponse{
		Status: http.StatusNoContent,
	}, nil
}
