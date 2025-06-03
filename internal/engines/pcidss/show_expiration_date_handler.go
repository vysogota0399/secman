package pcidss

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) ShowExpiryDateHandler(ctx context.Context, req *secman.LogicalRequest, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["pan_token"]
	expiryDateToken := params.Params["expiry_date_token"]

	expiryDate, ok, err := b.repo.ValueOk(ctx, cardToken+"/expiry_date/"+expiryDateToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get expiry date: %w", err)
	}

	if !ok {
		return &secman.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "expiry date not found"},
		}, nil
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": expiryDate},
	}, nil
}
