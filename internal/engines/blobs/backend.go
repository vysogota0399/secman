package blobs

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"sync"
	"sync/atomic"

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
	Data map[string]string `json:"data"`
}

func (b *Backend) Paths() map[string]map[string]*secman.Path {
	return map[string]map[string]*secman.Path{
		http.MethodGet: {
			PATH + "/:key": {
				Handler:     nil,
				Description: "Get a blob",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key of the blob",
					},
				},
			},
			PATH + "/:key/metadata": {
				Handler:     nil,
				Description: "Get the metadata of a blob",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key of the blob",
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
			PATH + "/:key": {
				Handler:     nil,
				Description: "Delete a blob",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key of the blob",
					},
				},
			},
		},
		http.MethodPut: {
			PATH + "/:key/metadata": {
				Handler:     nil,
				Description: "Update the metadata of a blob",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key of the blob",
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
	URL      string `json:"url" binding:"required"`
	User     string `json:"user" binding:"required"`
	Password string `json:"password" binding:"required"`
	SSL      bool   `json:"ssl" binding:"required"`
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
		return nil, fmt.Errorf("blobs: enable failed error when binding json %w", err)
	}

	if err := b.repo.Enable(ctx, blobParams); err != nil {
		return nil, fmt.Errorf("blobs: enable failed error when enabling %w", err)
	}

	blobParams.Adapter.Bucket = path.Join(b.repo.path, blobParams.Adapter.Bucket)
	b.blobParams = blobParams

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

	if !ok {
		return fmt.Errorf("blobs: post unseal failed error: %w", secman.ErrEngineIsNotEnabled)
	}

	s3, err := NewMinio(b.lg, b)
	if err != nil {
		return fmt.Errorf("blobs: post unseal failed error when creating minio client %w", err)
	}

	b.s3 = s3

	b.blobParams = params
	b.exist.Store(true)

	return nil
}
