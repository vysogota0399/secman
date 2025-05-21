package kv

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/vysogota0399/secman/internal/secman"
)

var _ secman.LogicalBackend = &Backend{}

type Backend struct {
	beMtx sync.RWMutex
	exist *atomic.Bool
}

const PATH = "/secrets/kv"

func (b *Backend) RootPath() string {
	return PATH
}

func (b *Backend) Help() string {
	return "KV backend, uses key-value pairs to store data"
}

func (b *Backend) Paths() map[string]map[string]*secman.Path {
	return map[string]map[string]*secman.Path{
		http.MethodGet: {
			PATH + "/:key": {
				Handler:     nil,
				Description: "Get a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to get",
						Required:    true,
					},
				},
			},
			PATH + "/:key/params": {
				Handler:     nil,
				Description: "Get the params of a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to get the params of",
						Required:    true,
					},
				},
			},
		},
		http.MethodPost: {
			PATH + "/": {
				Handler:     nil,
				Description: "Create a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to create",
						Required:    true,
					},
					{
						Name:        "value",
						Description: "The value to create",
						Required:    true,
					},
				},
			},
		},
		http.MethodDelete: {
			PATH + "/:key": {
				Handler:     nil,
				Description: "Delete a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to delete",
						Required:    true,
					},
				},
			},
		},
		http.MethodPut: {
			PATH + "/:key/params": {
				Handler:     nil,
				Description: "Update a key-value pair",
				Fields: []secman.Field{
					{
						Name:        "key",
						Description: "The key to update",
						Required:    true,
					},
				},
			},
		},
	}
}

func (b *Backend) Enable(ctx context.Context, req *secman.LogicalRequest) (*secman.LogicalResponse, error) {
	return nil, nil
}

func (b *Backend) PostUnseal(ctx context.Context) error {
	return nil
}
