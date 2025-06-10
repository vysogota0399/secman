package pcidss

import (
	"context"

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
		storage: server.NewLogicalStorage(b, "secrets/pci_dss"),
	}
}

func (r *Repository) ValueOk(ctx context.Context, key string) (string, bool, error) {
	entry, ok, err := r.storage.GetOk(ctx, key)
	if err != nil {
		return "", false, err
	}
	return entry.Value, ok, nil
}

func (r *Repository) Create(ctx context.Context, key string, value string) error {
	if err := r.storage.Update(ctx, key, server.Entry{Value: value, Key: key}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) Delete(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		if err := r.storage.Delete(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

func (r *Repository) IsExist(ctx context.Context) (bool, error) {
	_, ok, err := r.storage.GetOk(ctx, "")
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (r *Repository) Enable(ctx context.Context) error {
	if err := r.storage.Update(ctx, "", server.Entry{}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) List(ctx context.Context, key string) ([]server.Entry, error) {
	entries, err := r.storage.List(ctx, key)
	if err != nil {
		return nil, err
	}

	return entries, nil
}
