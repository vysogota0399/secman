package bariers

import (
	"context"
	"encoding/json"
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
	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("meta barrier: failed to marshal entry: %w", err)
	}

	return b.storage.Update(ctx, path, secman.PhysicalEntry{Value: value}, ttl)
}

func (b *UnsealedBarrier) Get(ctx context.Context, path string) (secman.Entry, error) {
	res, err := b.storage.Get(ctx, path)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("meta barrier: get key %s failed error: %w", path, err)
	}

	entry := secman.Entry{}
	err = json.Unmarshal(res.Value, &entry)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("meta barrier: key %s, value %s is not a valid entry: %w", path, string(res.Value), err)
	}

	return entry, nil
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
		entry := secman.Entry{}
		err = json.Unmarshal(pe.Value, &entry)
		if err != nil {
			return nil, fmt.Errorf("meta barrier: key %s, value %s is not a valid entry: %w", pe.Key, string(pe.Value), err)
		}

		entries[i] = entry
	}

	return entries, nil
}
