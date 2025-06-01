package bariers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vysogota0399/secman/internal/secman"
)

type UnsealedBarrier struct {
	storage secman.IStorage
}

func NewUnsealedBarrier(storage secman.IStorage) *UnsealedBarrier {
	return &UnsealedBarrier{storage: storage}
}

var _ secman.BarrierStorage = &UnsealedBarrier{}

func (b *UnsealedBarrier) Delete(ctx context.Context, path string) error {
	return b.storage.Delete(ctx, path)
}

func (b *UnsealedBarrier) Update(ctx context.Context, path string, entry secman.Entry, ttl time.Duration) error {
	return b.storage.Update(ctx, path, secman.PhysicalEntry{Value: []byte(entry.Value)}, ttl)
}

func (b *UnsealedBarrier) Get(ctx context.Context, path string) (secman.Entry, error) {
	res, err := b.storage.Get(ctx, path)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("meta barrier: get key %s failed error: %w", path, err)
	}

	return secman.Entry{Value: string(res.Value), Path: res.Path}, nil
}

func (b *UnsealedBarrier) GetOk(ctx context.Context, path string) (secman.Entry, bool, error) {
	entry, err := b.Get(ctx, path)
	if err != nil {
		if errors.Is(err, secman.ErrEntryNotFound) {
			return secman.Entry{}, false, nil
		}

		return secman.Entry{}, false, err
	}

	return entry, true, nil
}

func (b *UnsealedBarrier) List(ctx context.Context, path string) ([]secman.Entry, error) {
	physicalEntries, err := b.storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	entries := make([]secman.Entry, len(physicalEntries))
	for i, pe := range physicalEntries {
		entries[i] = secman.Entry{Value: string(pe.Value), Path: pe.Path}
	}

	return entries, nil
}
