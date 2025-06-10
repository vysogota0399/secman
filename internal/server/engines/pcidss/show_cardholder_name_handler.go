package pcidss

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
)

func (b *Backend) ShowCardholderNameHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	cardToken := params.Params["pan_token"]
	cardholderNameToken := params.Params["cardholder_name_token"]

	cardholderName, ok, err := b.repo.ValueOk(ctx, cardToken+"/cardholder_name/"+cardholderNameToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get cardholder name: %w", err)
	}

	if !ok {
		return &server.LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "cardholder name not found"},
		}, nil
	}

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"value": cardholderName},
	}, nil
}
