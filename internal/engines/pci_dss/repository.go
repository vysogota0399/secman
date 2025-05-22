package pci_dss

import (
	"context"

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
		path:    "secrets/pci_dss",
	}
}

func (r *Repository) ValueOk(ctx context.Context, key string) (string, bool, error) {
	entry, ok, err := r.barrier.GetOk(ctx, r.path+"/"+key)
	if err != nil {
		return "", false, err
	}
	return entry.Value, ok, nil
}

func (r *Repository) Create(ctx context.Context, key string, value string) error {
	if err := r.barrier.Update(ctx, r.path+"/"+key, secman.Entry{
		Path:  r.path + "/" + key,
		Value: value,
	}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) Delete(ctx context.Context, keys ...string) error {
	for _, key := range keys {
		if err := r.barrier.Delete(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

func (r *Repository) IsExist(ctx context.Context) (bool, error) {
	_, ok, err := r.barrier.GetOk(ctx, r.path)
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (r *Repository) Enable(ctx context.Context) error {
	if err := r.barrier.Update(ctx, r.path, secman.Entry{
		Path:  r.path,
		Value: "",
	}, 0); err != nil {
		return err
	}

	return nil
}

func (r *Repository) List(ctx context.Context, key string) ([]secman.Entry, error) {
	entries, err := r.barrier.List(ctx, r.path+"/"+key)
	if err != nil {
		return nil, err
	}

	return entries, nil
}
