package blobs

import (
	"context"
	"encoding/json"

	"github.com/vysogota0399/secman/internal/secman"
)

type MetadataRepository struct {
	storage secman.IStorage
}

func NewMetadataRepository(storage secman.IStorage) *MetadataRepository {
	return &MetadataRepository{storage: storage}
}

func (r *MetadataRepository) Get(ctx context.Context, path string) (map[string]any, error) {
	entry, err := r.storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}

	var metadata map[string]any
	if err := json.Unmarshal(entry.Value, &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

func (r *MetadataRepository) Update(ctx context.Context, path string, value map[string]string) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.storage.Update(ctx, path, secman.PhysicalEntry{Value: jsonValue}, 0)
}

func (r *MetadataRepository) Delete(ctx context.Context, path string) error {
	return r.storage.Delete(ctx, path)
}
