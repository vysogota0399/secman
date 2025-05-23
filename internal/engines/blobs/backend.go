package blobs

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

var _ secman.LogicalBackend = &Backend{}

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

func NewBackend(lg *logging.ZapLogger, blobRepo *Repository, metadataRepo *MetadataRepository) *Backend {
	exist := &atomic.Bool{}
	exist.Store(false)

	return &Backend{
		lg:       lg,
		repo:     blobRepo,
		metadata: metadataRepo,
		exist:    exist,
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
	Adapter S3Adapter `json:"adapter" binding:"required"`
}

type S3Adapter struct {
	URL      string `json:"url"`
	User     string `json:"user"`
	Password string `json:"password"`
	SSL      bool   `json:"ssl"`
	Bucket   string `json:"bucket"`
}

func (b *Backend) Enable(ctx context.Context, req *secman.LogicalRequest) (*secman.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	if b.exist.Load() {
		return &secman.LogicalResponse{
			Status:  http.StatusNotModified,
			Message: "blobs: already enabled",
		}, nil
	}

	blobParams := &BlobParams{}

	if err := req.ShouldBindJSON(blobParams); err != nil {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "invalid request",
		}, nil
	}

	adapter := blobParams.Adapter

	if adapter.URL == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "invalid request, missing required field: url",
		}, nil
	}

	if adapter.User == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "invalid request, missing required field: user",
		}, nil
	}

	if adapter.Password == "" {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "invalid request, missing required field: password",
		}, nil
	}

	if adapter.SSL {
		return &secman.LogicalResponse{
			Status:  http.StatusBadRequest,
			Message: "invalid request, missing required field: ssl",
		}, nil
	}
	blobParams.Adapter.Bucket = strings.ReplaceAll(b.RootPath(), "/", "-")

	if err := b.repo.Enable(ctx, blobParams); err != nil {
		return nil, fmt.Errorf("blobs: enable failed error when enabling %w", err)
	}

	b.blobParams = blobParams

	s3, err := NewMinio(b.lg, b)
	if err != nil {
		return nil, fmt.Errorf("blobs: enable failed error when creating minio client %w", err)
	}

	b.s3 = s3
	b.exist.Store(true)

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: "blobs enabled",
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

	s3, err := NewMinio(b.lg, b)
	if err != nil {
		return fmt.Errorf("blobs: post unseal failed error when creating minio client %w", err)
	}

	b.s3 = s3

	b.exist.Store(true)

	return nil
}

func (b *Backend) rndToken() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	bytes := make([]byte, 64)
	rnd.Read(bytes)

	res := base64.StdEncoding.EncodeToString(bytes)

	return strings.ReplaceAll(res, "/", "_")
}
