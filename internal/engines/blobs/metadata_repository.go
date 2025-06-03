package blobs

import (
	"context"
	"encoding/json"
	"errors"
	"path"

	"github.com/vysogota0399/secman/internal/secman"
)

type MetadataRepository struct {
	storage secman.BarrierStorage
	postfix string
	prefix  string
}

func NewMetadataRepository(storage secman.BarrierStorage) *MetadataRepository {
	return &MetadataRepository{storage: storage, postfix: "metadata", prefix: "unsealed/secrets/blobs"}
}

func (r *MetadataRepository) Get(ctx context.Context, path string) (map[string]string, error) {
	entry, err := r.storage.Get(ctx, r.path(path))
	if err != nil {
		return nil, err
	}

	var metadata map[string]string
	if err := json.Unmarshal([]byte(entry.Value), &metadata); err != nil {
		return nil, err
	}

	return metadata, nil
}

func (r *MetadataRepository) GetOk(ctx context.Context, key string) (map[string]string, bool, error) {
	entry, err := r.Get(ctx, key)
	if err != nil {
		if errors.Is(err, secman.ErrEntryNotFound) {
			return nil, false, nil
		}

		return nil, false, err
	}

	return entry, true, nil
}

func (r *MetadataRepository) Update(ctx context.Context, key string, value map[string]string) error {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return err
	}

	return r.storage.Update(ctx, r.path(key), secman.Entry{Value: string(jsonValue)}, 0)
}

func (r *MetadataRepository) Delete(ctx context.Context, key string) error {
	return r.storage.Delete(ctx, r.path(key))
}

func (r *MetadataRepository) path(key string) string {
	return path.Join(r.prefix, key, r.postfix)
}
