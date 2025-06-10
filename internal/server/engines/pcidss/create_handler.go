package pcidss

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
	"go.uber.org/zap"
)

func (b *Backend) CreateHandler(ctx context.Context, req *server.LogicalRequest, params *server.LogicalParams) (*server.LogicalResponse, error) {
	b.beMtx.RLock()
	defer b.beMtx.RUnlock()

	createParams, ok := params.Body.(*CreateCardBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", params.Body)
	}

	// Validate input
	if err := b.validateCardData(ctx, &createParams.CardData); err != nil {
		return &server.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: gin.H{"error": err.Error()},
		}, nil
	}

	// Create tokens map to track created resources for cleanup
	createdTokens := make(map[string]string)

	// Process PAN first as it's the main entity
	panToken, err := b.processCreatePan(ctx, &createParams.CardData)
	if err != nil {
		if errors.Is(err, server.ErrLogicalResponse) {
			return &server.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}
		return nil, err
	}
	createdTokens["pan"] = panToken

	// Update metadata
	if err := b.metadata.Update(ctx, panToken, map[string]string{"created_at": time.Now().Format(time.RFC3339)}); err != nil {
		b.cleanupCreatedTokens(ctx, createdTokens)
		return nil, fmt.Errorf("failed to update metadata: %w", err)
	}

	// Process cardholder name
	cardholderNameToken, err := b.processCreateCardholderName(ctx, &createParams.CardData, panToken)
	if err != nil {
		b.cleanupCreatedTokens(ctx, createdTokens)
		if errors.Is(err, server.ErrLogicalResponse) {
			return &server.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}
		return nil, err
	}
	createdTokens["cardholder_name"] = cardholderNameToken

	// Process expiry date
	expiryDateToken, err := b.processCreateExpiryDate(ctx, &createParams.CardData, panToken)
	if err != nil {
		b.cleanupCreatedTokens(ctx, createdTokens)
		if errors.Is(err, server.ErrLogicalResponse) {
			return &server.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}
		return nil, err
	}
	createdTokens["expiry_date"] = expiryDateToken

	// Process security code
	securityCodeToken, err := b.processCreateSecurityCode(ctx, &createParams.CardData, panToken)
	if err != nil {
		b.cleanupCreatedTokens(ctx, createdTokens)
		if errors.Is(err, server.ErrLogicalResponse) {
			return &server.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": err.Error()},
			}, nil
		}
		return nil, err
	}
	createdTokens["security_code"] = securityCodeToken

	return &server.LogicalResponse{
		Status: http.StatusOK,
		Message: gin.H{
			"pan":             panToken,
			"cardholder_name": cardholderNameToken,
			"expiry_date":     expiryDateToken,
			"security_code":   securityCodeToken,
		},
	}, nil
}

func (b *Backend) validateCardData(ctx context.Context, data *CardData) error {
	if data.PAN == "" {
		return fmt.Errorf("PAN is required")
	}

	if data.CardholderName == "" {
		return fmt.Errorf("cardholder name is required")
	}

	if data.ExpiryDate == "" {
		return fmt.Errorf("expiry date is required")
	}

	if _, err := time.Parse(time.RFC3339Nano, data.ExpiryDate); err != nil {
		b.lg.ErrorCtx(ctx, "invalid expiry date format", zap.Error(err))
		return fmt.Errorf("invalid expiry date format, expected RFC3339Nano")
	}

	if data.SecurityCode == "" {
		return fmt.Errorf("security code is required")
	}

	return nil
}

func (b *Backend) cleanupCreatedTokens(ctx context.Context, tokens map[string]string) {
	token := tokens["pan"]
	// Delete all associated tokens first
	if cardholderName, ok := tokens["cardholder_name"]; ok {
		b.repo.Delete(ctx, token+"/cardholder_name/"+cardholderName)
	}
	if expiryDate, ok := tokens["expiry_date"]; ok {
		b.repo.Delete(ctx, token+"/expiry_date/"+expiryDate)
	}
	if securityCode, ok := tokens["security_code"]; ok {
		b.repo.Delete(ctx, token+"/security_code/"+securityCode)
	}
	// Delete the PAN token last
	b.repo.Delete(ctx, token)
}

func (b *Backend) processCreatePan(ctx context.Context, data *CardData) (string, error) {
	panToken := b.hashToken(data.PAN)
	_, ok, err := b.repo.ValueOk(ctx, panToken)
	if err != nil {
		return "", fmt.Errorf("failed to get pan token: %w", err)
	}

	if ok {
		return "", errors.Join(server.ErrLogicalResponse, fmt.Errorf("such PAN already exists"))
	}

	if err := b.repo.Create(ctx, panToken, data.PAN); err != nil {
		return "", fmt.Errorf("failed to create pan token: %w", err)
	}

	return panToken, nil
}

func (b *Backend) processCreateCardholderName(ctx context.Context, data *CardData, panToken string) (string, error) {
	cardholderNameToken := b.rndToken()

	if err := b.repo.Create(ctx, panToken+"/cardholder_name/"+cardholderNameToken, data.CardholderName); err != nil {
		return "", fmt.Errorf("failed to create cardholder name token: %w", err)
	}

	return cardholderNameToken, nil
}

func (b *Backend) processCreateExpiryDate(ctx context.Context, data *CardData, panToken string) (string, error) {
	expiryDateToken := b.rndToken()

	expireAt, err := time.Parse(time.RFC3339Nano, data.ExpiryDate)
	if err != nil {
		return "", errors.Join(server.ErrLogicalResponse, fmt.Errorf("invalid expiry date format, expected RFC3339Nano, got %w", err))
	}

	if err := b.repo.Create(ctx, panToken+"/expiry_date/"+expiryDateToken, expireAt.Format("06/01")); err != nil {
		return "", fmt.Errorf("failed to create expiry date token: %w", err)
	}

	return expiryDateToken, nil
}

func (b *Backend) processCreateSecurityCode(ctx context.Context, data *CardData, panToken string) (string, error) {
	securityCodeToken := b.rndToken()

	if err := b.repo.Create(ctx, panToken+"/security_code/"+securityCodeToken, data.SecurityCode); err != nil {
		return "", fmt.Errorf("failed to create security code token: %w", err)
	}

	return securityCodeToken, nil
}
