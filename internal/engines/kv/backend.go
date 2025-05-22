package kv

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

var _ secman.LogicalBackend = &Backend{}

type Backend struct {
	beMtx    sync.RWMutex
	exist    *atomic.Bool
	router   *secman.BackendRouter
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

const PATH = "/secrets/kv"

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
	return "KV backend, uses key-value pairs to store data"
}

type CreateSecretBody struct {
	Key   string `json:"key" binding:"required"`
	Value string `json:"value" binding:"required"`
}

type MetadataBody struct {
	Metadata map[string]string `json:"metadata"`
}

func (b *Backend) Paths() map[string]map[string]*secman.Path {
	return map[string]map[string]*secman.Path{
		http.MethodGet: {
			PATH + "/:key": {
				Handler:     b.ShowHandler,
				Description: "Get a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to get",
					},
				},
			},
			PATH + "/:key/metadata": {
				Handler:     b.ShowMetadataHandler,
				Description: "Get the metadata of a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to get the metadata of",
					},
				},
			},
			PATH: {
				Handler:     b.IndexHandler,
				Description: "Get all key-value pairs",
			},
		},
		http.MethodPost: {
			PATH: {
				Handler:     b.CreateHandler,
				Description: "Create a key-value pair",
				Body:        func() any { return &CreateSecretBody{} },
			},
		},
		http.MethodDelete: {
			PATH + "/:key": {
				Handler:     b.DeleteHandler,
				Description: "Delete a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to delete",
					},
				},
			},
		},
		http.MethodPut: {
			PATH + "/:key/metadata": {
				Handler:     b.UpdateMetadataHandler,
				Description: "Update a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to update",
					},
				},
				Body: func() any { return &MetadataBody{} },
			},
		},
	}
}

func (b *Backend) Enable(ctx context.Context, req *secman.LogicalRequest) (*secman.LogicalResponse, error) {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	if b.exist.Load() {
		return &secman.LogicalResponse{
			Status:  http.StatusNotModified,
			Message: "kv: already enabled",
		}, nil
	}

	if err := b.repo.Enable(ctx); err != nil {
		return nil, fmt.Errorf("kv: enable failed error when enabling %w", err)
	}

	b.exist.Store(true)

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: "kv enabled",
	}, nil
}

func (b *Backend) PostUnseal(ctx context.Context) error {
	b.beMtx.Lock()
	defer b.beMtx.Unlock()

	ok, err := b.repo.IsExist(ctx)
	if err != nil {
		return fmt.Errorf("kv: post unseal failed error when checking if engine is enabled %w", err)
	}

	if !ok {
		return fmt.Errorf("kv: post unseal failed error: %w", secman.ErrEngineIsNotEnabled)
	}

	b.exist.Store(true)

	return nil
}
