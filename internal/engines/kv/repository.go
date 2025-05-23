package kv

import (
	"context"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type Repository struct {
	lg      *logging.ZapLogger
	storage secman.ILogicalStorage
}

func NewLogicalStorage(b secman.IBarrier) secman.ILogicalStorage {
	return secman.NewLogicalStorage(b, "secrets/kv")
}

func NewRepository(lg *logging.ZapLogger, storage secman.ILogicalStorage) *Repository {
	return &Repository{
		lg:      lg,
		storage: storage,
	}
}

func (r *Repository) ValueOk(ctx context.Context, key string) (string, bool, error) {
	entry, ok, err := r.storage.GetOk(ctx, key)
	if err != nil {
		return "", false, err
	}
	return entry.Value, ok, nil
}

func (r *Repository) List(ctx context.Context) ([]secman.Entry, error) {
	entries, err := r.storage.List(ctx, "")
	if err != nil {
		return nil, err
	}

	return entries, nil
}

func (r *Repository) Create(ctx context.Context, key string, value string) error {
	if err := r.storage.Update(ctx, key, secman.Entry{
		Value: value,
		Key:   key,
	}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) Delete(ctx context.Context, key string) error {
	return r.storage.Delete(ctx, key)
}

func (r *Repository) IsExist(ctx context.Context) (bool, error) {
	_, ok, err := r.storage.GetOk(ctx, "")
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (r *Repository) Enable(ctx context.Context) error {
	if err := r.storage.Update(ctx, "", secman.Entry{}, 0); err != nil {
		return err
	}

	return nil
}
