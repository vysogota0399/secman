package pci_dss

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) ShowSecurityCodeHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["card_token"]
	securityCodeToken := params.Params["security_code_token"]

	securityCode, ok, err := b.repo.ValueOk(ctx, cardToken+"/security_code/"+securityCodeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get security code: %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "security code not found"},
		}, nil
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"security_code": securityCode},
	}, nil
}
