package pci_dss

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) CreateHandler(ctx *gin.Context, params *secman.LogicalParams) (*secman.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	createParams, ok := params.Body.(*CreateCardBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	data := createParams.CardData
	panToken, err := b.processCreatePan(ctx, &data)
	if err != nil {
		if errors.Is(err, secman.ErrLogicalResponse) {
			return &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}

		return nil, err
	}

	cardholderNameToken, err := b.processCreateCardholderName(ctx, &data, panToken)
	if err != nil {
		if errors.Is(err, secman.ErrLogicalResponse) {
			return &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}

		return nil, err
	}

	expiryDateToken, err := b.processCreateExpiryDate(ctx, &data, panToken)
	if err != nil {
		if errors.Is(err, secman.ErrLogicalResponse) {
			return &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}

		return nil, err
	}

	securityCodeToken, err := b.processCreateSecurityCode(ctx, &data, panToken)
	if err != nil {
		if errors.Is(err, secman.ErrLogicalResponse) {
			return &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}

		return nil, err
	}

	return &secman.LogicalResponse{
		Status: http.StatusOK,
		Message: gin.H{
			"pan":             panToken,
			"cardholder_name": cardholderNameToken,
			"expiry_date":     expiryDateToken,
			"security_code":   securityCodeToken,
		},
	}, nil
}

func (b *Backend) processCreatePan(ctx *gin.Context, data *CardData) (string, error) {
	if data.PAN == "" {
		return "", errors.Join(secman.ErrLogicalResponse, fmt.Errorf("PAN is required"))
	}

	panToken := b.hashToken(data.PAN)
	_, ok, err := b.repo.ValueOk(ctx, panToken)
	if err != nil {
		return "", fmt.Errorf("failed to get pan token: %w", err)
	}

	if ok {
		return "", errors.Join(secman.ErrLogicalResponse, fmt.Errorf("such PAN already exists"))
	}

	if err := b.repo.Create(ctx, panToken, data.PAN); err != nil {
		return "", fmt.Errorf("failed to create pan token: %w", err)
	}

	return panToken, nil
}

func (b *Backend) processCreateCardholderName(ctx *gin.Context, data *CardData, panToken string) (string, error) {
	cardholderNameToken := b.rndToken()

	if err := b.repo.Create(ctx, panToken+"/cardholder_name/"+cardholderNameToken, data.CardholderName); err != nil {
		return "", fmt.Errorf("failed to create cardholder name token: %w", err)
	}

	return cardholderNameToken, nil
}

func (b *Backend) processCreateExpiryDate(ctx *gin.Context, data *CardData, panToken string) (string, error) {
	expiryDateToken := b.rndToken()

	expireAt, err := time.Parse(time.RFC3339Nano, data.ExpiryDate)
	if err != nil {
		return "", errors.Join(secman.ErrLogicalResponse, fmt.Errorf("invalid expiry date format, expected RFC3339Nano, got %w", err))
	}

	if err := b.repo.Create(ctx, panToken+"/expiry_date/"+expiryDateToken, expireAt.Format("06/01")); err != nil {
		return "", fmt.Errorf("failed to create expiry date token: %w", err)
	}

	return expiryDateToken, nil
}

func (b *Backend) processCreateSecurityCode(ctx *gin.Context, data *CardData, panToken string) (string, error) {
	securityCodeToken := b.rndToken()

	if err := b.repo.Create(ctx, panToken+"/security_code/"+securityCodeToken, data.SecurityCode); err != nil {
		return "", fmt.Errorf("failed to create security code token: %w", err)
	}

	return securityCodeToken, nil
}
