package pcidss

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/cryptoutils"
)

var _ server.LogicalBackend = &Backend{}

type Backend struct {
	beMtx    sync.RWMutex
	exist    *atomic.Bool
	router   *server.BackendRouter
	repo     *Repository
	metadata *MetadataRepository
	lg       *logging.ZapLogger
}

func NewBackend(lg *logging.ZapLogger, repo *Repository, metadata *MetadataRepository) *Backend {
	return &Backend{
		lg:       lg,
		repo:     repo,
		metadata: metadata,
		exist:    &atomic.Bool{},
		beMtx:    sync.RWMutex{},
	}
}

const PATH = "/secrets/pci_dss"

func (b *Backend) RootPath() string {
	return PATH
}

func (b *Backend) Router() *server.BackendRouter {
	return b.router
}

func (b *Backend) SetRouter(router *server.BackendRouter) {
	b.router = router
}

func (b *Backend) Help() string {
	return `The PCI DSS backend is a specialized module designed to handle sensitive payment card data in compliance with PCI DSS requirements.`
}

type CardData struct {
	// Primary Account Number (PAN)
	PAN string `json:"pan"` // Encrypted

	// Cardholder Data
	CardholderName string `json:"cardholder_name"` // Encrypted
	ExpiryDate     string `json:"expiry_date"`     // MM/YY format, encrypted
	CreatedAt      string `json:"created_at"`      // ISO 8601 format

	// Security Code (CVV/CVC/CID)
	SecurityCode string `json:"security_code,omitempty"` // Encrypted, temporary
}

type CreateCardBody struct {
	CardData CardData `json:"card_data"`
}

type MetadataBody struct {
	Metadata map[string]string `json:"metadata"`
}

func (b *Backend) Paths() map[string]map[string]*server.Path {
	return map[string]map[string]*server.Path{
		http.MethodGet: {
			PATH: {
				Handler:     b.indexHandler,
				Description: "Get a list of cards",
			},
			PATH + "/:pan_token/metadata": {
				Handler:     b.ShowMetadataHandler,
				Description: "Get the metadata of a card",
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The token of the card",
					},
				},
			},

			PATH + "/:pan_token": {
				Handler:     b.ShowPanHandler,
				Description: "Get the PAN of a card",
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The pan token of the card",
					},
				},
			},

			PATH + "/:pan_token/cardholder_name/:cardholder_name_token": {
				Handler:     b.ShowCardholderNameHandler,
				Description: "Get the cardholder name of a card",
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The pan token of the card",
					},
					{
						Name:        "cardholder_name_token",
						Description: "The token of the cardholder name",
					},
				},
			},

			PATH + "/:pan_token/expiry_date/:expiry_date_token": {
				Handler:     b.ShowExpiryDateHandler,
				Description: "Get the expiry date of a card",
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The pan token of the card",
					},
					{
						Name:        "expiry_date_token",
						Description: "The token of the expiry date",
					},
				},
			},

			PATH + "/:pan_token/security_code/:security_code_token": {
				Handler:     b.ShowSecurityCodeHandler,
				Description: "Get the security code of a card",
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The pan token of the card",
					},
					{
						Name:        "security_code_token",
						Description: "The token of the security code",
					},
				},
			},
		},
		http.MethodPost: {
			PATH: {
				Handler:     b.CreateHandler,
				Description: "Create a card",
				Body:        func() any { return &CreateCardBody{} },
			},
		},
		http.MethodDelete: {
			PATH + "/:pan_token": {
				Handler:     b.DeleteHandler,
				Description: "Delete a card",
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The key to delete",
					},
				},
			},
		},
		http.MethodPut: {
			PATH + "/:pan_token/metadata": {
				Handler:     b.UpdateMetadataHandler,
				Description: "Update a card metadata",
				Body:        func() any { return &MetadataBody{} },
				Fields: []server.Field{
					{
						Name:        "pan_token",
						Description: "The key to update",
					},
				},
			},
		},
	}
}

func (b *Backend) Enable(ctx context.Context, req *server.LogicalRequest) (*server.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	if b.exist.Load() {
		return &server.LogicalResponse{
			Status:  http.StatusNotModified,
			Message: gin.H{"message": "pci_dss: already enabled"},
		}, nil
	}

	if err := b.repo.Enable(ctx); err != nil {
		return nil, fmt.Errorf("pci_dss: enable failed error when enabling %w", err)
	}

	b.exist.Store(true)

	return &server.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"message": "pci_dss enabled"},
	}, nil
}

func (b *Backend) PostUnseal(ctx context.Context) error {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	ok, err := b.repo.IsExist(ctx)
	if err != nil {
		return fmt.Errorf("pci_dss: post unseal failed error when checking if engine is enabled %w", err)
	}

	if !ok {
		return fmt.Errorf("pci_dss: post unseal failed error: %w", server.ErrEngineIsNotEnabled)
	}

	b.exist.Store(true)

	return nil
}

func (b *Backend) hashToken(token string) string {
	hash := sha256.New()
	hash.Write([]byte(token))
	return hex.EncodeToString(hash.Sum(nil))
}

func (b *Backend) rndToken() string {
	res := base64.StdEncoding.EncodeToString(cryptoutils.GenerateRandom(64))

	return strings.ReplaceAll(res, "/", "_")
}
