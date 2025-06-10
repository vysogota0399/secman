package bariers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/vysogota0399/secman/internal/server"
)

// UnsealedBarrier имплементирует интерфейс IBarrier, но не использует шифрование. Он может быть использоваон для хранение метаданных.
type UnsealedBarrier struct {
	storage server.IStorage
}

func NewUnsealedBarrier(storage server.IStorage) *UnsealedBarrier {
	return &UnsealedBarrier{storage: storage}
}

var _ server.BarrierStorage = &UnsealedBarrier{}

func (b *UnsealedBarrier) Delete(ctx context.Context, path string) error {
	return b.storage.Delete(ctx, path)
}

func (b *UnsealedBarrier) Update(ctx context.Context, path string, entry server.Entry, ttl time.Duration) error {
	return b.storage.Update(ctx, path, server.PhysicalEntry{Value: []byte(entry.Value)}, ttl)
}

func (b *UnsealedBarrier) Get(ctx context.Context, path string) (server.Entry, error) {
	res, err := b.storage.Get(ctx, path)
	if err != nil {
		return server.Entry{}, fmt.Errorf("meta barrier: get key %s failed error: %w", path, err)
	}

	return server.Entry{Value: string(res.Value), Path: res.Path}, nil
}

func (b *UnsealedBarrier) GetOk(ctx context.Context, path string) (server.Entry, bool, error) {
	entry, err := b.Get(ctx, path)
	if err != nil {
		if errors.Is(err, server.ErrEntryNotFound) {
			return server.Entry{}, false, nil
		}

		return server.Entry{}, false, err
	}

	return entry, true, nil
}

func (b *UnsealedBarrier) List(ctx context.Context, path string) ([]server.Entry, error) {
	physicalEntries, err := b.storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	entries := make([]server.Entry, len(physicalEntries))
	for i, pe := range physicalEntries {
		entries[i] = server.Entry{Value: string(pe.Value), Path: pe.Path}
	}

	return entries, nil
}
