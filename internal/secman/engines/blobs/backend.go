package blobs

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/cryptoutils"
	"go.uber.org/zap"
)

var _ secman.LogicalBackend = &Backend{}

type S3 interface {
	Start(ba *Backend) error
	Create(ctx context.Context, blob *Blob) error
	Get(ctx context.Context, key string) (*Blob, error)
	Delete(ctx context.Context, key string) error
}

type Backend struct {
	beMtx      sync.RWMutex
	exist      *atomic.Bool
	router     *secman.BackendRouter
	repo       *Repository
	metadata   *MetadataRepository
	lg         *logging.ZapLogger
	blobParams *BlobParams
	s3         S3
}

func NewBackend(lg *logging.ZapLogger, blobRepo *Repository, metadataRepo *MetadataRepository, s3 S3) *Backend {
	exist := &atomic.Bool{}
	exist.Store(false)

	return &Backend{
		lg:       lg,
		repo:     blobRepo,
		metadata: metadataRepo,
		exist:    exist,
		s3:       s3,
	}
}

const PATH = "/secrets/blobs"

func (b *Backend) RootPath() string {
	return PATH
}

func (b *Backend) Router() *secman.BackendRouter {
	return b.router
}

func (b *Backend) SetRouter(router *secman.BackendRouter) {
	b.router = router
}

func (b *Backend) Help() string {
	return "Blobs backend, uses key-value pairs to store data in S3-compatible storage"
}

type MetadataBody struct {
	Metadata map[string]string `json:"metadata"`
}

func (b *Backend) Paths() map[string]map[string]*secman.Path {
	return map[string]map[string]*secman.Path{
		http.MethodGet: {
			PATH: {
				Handler:     b.indexHandler,
				Description: "Get a list of blobs",
			},
			PATH + "/:token": {
				Handler:     b.showBlob,
				Description: "Get a blob",
				Fields: []secman.Field{
					{
						Name:        "token",
						Description: "The token of the blob",
					},
				},
			},
			PATH + "/:token/metadata": {
				Handler:     b.showMetadataHandler,
				Description: "Get the metadata of a blob",
				Fields: []secman.Field{
					{
						Name:        "token",
						Description: "The token of the blob",
					},
				},
			},
		},
		http.MethodPost: {
			PATH: {
				Handler:     b.createHandler,
				Description: "Create a blob",
				Body:        func() any { return &MetadataBody{} },
			},
		},
		http.MethodDelete: {
			PATH + "/:token": {
				Handler:     b.deleteHandler,
				Description: "Delete a blob",
				Fields: []secman.Field{
					{
						Name:        "token",
						Description: "The token of the blob",
					},
				},
			},
		},
		http.MethodPut: {
			PATH + "/:token/metadata": {
				Handler:     b.updateMetadataHandler,
				Description: "Update the metadata of a blob",
				Fields: []secman.Field{
					{
						Name:        "token",
						Description: "The token of the blob",
					},
				},
				Body: func() any { return &MetadataBody{} },
			},
		},
	}
}

type BlobParams struct {
	S3URL    string `json:"s3_url"`
	S3User   string `json:"s3_user"`
	S3Pass   string `json:"s3_pass"`
	S3SSL    string `json:"s3_ssl"`
	S3Bucket string `json:"s3_bucket"`
}

func (b *Backend) Enable(ctx context.Context, req *secman.LogicalRequest) (*secman.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	if b.exist.Load() {
		return &secman.LogicalResponse{
			Status:  http.StatusNotModified,
			Message: gin.H{"error": "blobs: already enabled"},
		}, nil
	}

	blobParams := &BlobParams{}

	if err := req.ShouldBindJSON(blobParams); err != nil {
		b.lg.DebugCtx(ctx, "blobs: enable failed error when binding json", zap.String("error", err.Error()))
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: gin.H{"error": "invalid request"},
		}, nil
	}

	if blobParams.S3URL == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: gin.H{"error": "invalid request, missing required field: s3_url"},
		}, nil
	}

	if blobParams.S3User == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: gin.H{"error": "invalid request, missing required field: s3_user"},
		}, nil
	}

	if blobParams.S3Pass == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: gin.H{"error": "invalid request, missing required field: s3_pass"},
		}, nil
	}

	if blobParams.S3SSL == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: gin.H{"error": "invalid request, missing required field: s3_ssl"},
		}, nil
	}
	blobParams.S3Bucket = strings.ReplaceAll(b.repo.storage.Prefix(), "/", "-")

	if err := b.repo.Enable(ctx, blobParams); err != nil {
		return nil, fmt.Errorf("blobs: enable failed error when enabling %w", err)
	}

	b.blobParams = blobParams

	if err := b.s3.Start(b); err != nil {
		return nil, fmt.Errorf("blobs: enable failed error when starting s3 %w", err)
	}

	b.exist.Store(true)

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"message": "blobs enabled"},
	}, nil
}

func (b *Backend) PostUnseal(ctx context.Context) error {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	params, ok, err := b.repo.IsExist(ctx)
	if err != nil {
		return fmt.Errorf("blobs: post unseal failed error when checking if engine is enabled %w", err)
	}
	b.blobParams = params

	if !ok {
		return fmt.Errorf("blobs: post unseal failed error: %w", secman.ErrEngineIsNotEnabled)
	}

	if err := b.s3.Start(b); err != nil {
		return fmt.Errorf("blobs: post unseal failed error when starting s3 %w", err)
	}

	b.exist.Store(true)

	return nil
}

func (b *Backend) rndToken() string {
	bytes := cryptoutils.GenerateRandom(64)
	res := base64.StdEncoding.EncodeToString(bytes)

	return strings.ReplaceAll(res, "/", "_")
}
