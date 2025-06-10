package blobs

import (
	"context"
	"encoding/json"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
)

type Repository struct {
	lg      *logging.ZapLogger
	storage server.ILogicalStorage
}

func NewRepository(b server.BarrierStorage, lg *logging.ZapLogger) *Repository {
	return &Repository{
		lg:      lg,
		storage: server.NewLogicalStorage(b, "secrets/blobs"),
	}
}

func (r *Repository) IsExist(ctx context.Context) (params *BlobParams, ok bool, err error) {
	entry, ok, err := r.storage.GetOk(ctx, "")
	if err != nil {
		return nil, false, err
	}

	if !ok {
		return nil, false, nil
	}

	if err := json.Unmarshal([]byte(entry.Value), &params); err != nil {
		return nil, false, err
	}

	return params, true, nil
}

func (r *Repository) Enable(ctx context.Context, params *BlobParams) error {
	jsonParams, err := json.Marshal(params)
	if err != nil {
		return err
	}

	if err := r.storage.Update(ctx, "", server.Entry{
		Value: string(jsonParams),
	}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) CreateBlob(ctx context.Context, key string, value string) error {
	if err := r.storage.Update(ctx, key, server.Entry{Value: value, Key: key}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) Delete(ctx context.Context, key string) error {
	return r.storage.Delete(ctx, key)
}

func (r *Repository) GetBlobKeyOk(ctx context.Context, key string) (string, bool, error) {
	entry, ok, err := r.storage.GetOk(ctx, key)
	if err != nil {
		return "", false, err
	}

	return entry.Value, ok, nil
}

func (r *Repository) List(ctx context.Context) ([]server.Entry, error) {
	entries, err := r.storage.List(ctx, "/")
	if err != nil {
		return nil, err
	}

	return entries, nil
}
