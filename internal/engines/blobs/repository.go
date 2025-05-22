package blobs

import (
	"context"
	"encoding/json"
	"path"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type Repository struct {
	lg      *logging.ZapLogger
	barrier secman.IBarrier
	path    string
}

func NewRepository(lg *logging.ZapLogger, barrier secman.IBarrier) *Repository {
	return &Repository{
		lg:      lg,
		barrier: barrier,
		path:    "secrets/blobs",
	}
}

func (r *Repository) IsExist(ctx context.Context) (params *BlobParams, ok bool, err error) {
	entry, ok, err := r.barrier.GetOk(ctx, r.path)
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

	if err := r.barrier.Update(ctx, r.path, secman.Entry{
		Path:  r.path,
		Value: string(jsonParams),
	}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) CreateBlob(ctx context.Context, key string, value string) error {
	secretPath := path.Join(r.path, key)
	if err := r.barrier.Update(ctx, secretPath, secman.Entry{
		Path:  secretPath,
		Value: value,
	}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) Delete(ctx context.Context, key string) error {
	secretPath := path.Join(r.path, key)
	return r.barrier.Delete(ctx, secretPath)
}

func (r *Repository) GetBlobKeyOk(ctx context.Context, key string) (string, bool, error) {
	secretPath := path.Join(r.path, key)
	entry, ok, err := r.barrier.GetOk(ctx, secretPath)
	if err != nil {
		return "", false, err
	}

	return entry.Value, ok, nil
}
