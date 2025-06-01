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

	cardToken := params.Params["pan_token"]

	paths, err := b.repo.List(ctx, cardToken)
	if err != nil {
		return nil, fmt.Errorf("failed to list paths: %w", err)
	}

	keysToDelete := make([]string, 0, len(paths))
	for _, path := range paths {
		keysToDelete = append(keysToDelete, path.Key)
	}

	b.repo.Delete(ctx, keysToDelete...)

	if err := b.metadata.Delete(ctx, cardToken); err != nil {
		return nil, fmt.Errorf("failed to delete metadata: %w", err)
	}

	return &secman.LogicalResponse{
		Status: http.StatusNoContent,
	}, nil
}
