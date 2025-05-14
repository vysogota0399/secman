package bariers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type DummyBarrier struct {
	secman.IStorage
	log    *logging.ZapLogger
	sealed *atomic.Bool
}

var _ secman.IBarrier = &DummyBarrier{}

func NewDummyBarrier(storage secman.IStorage, log *logging.ZapLogger) *DummyBarrier {
	sealed := &atomic.Bool{}
	sealed.Store(true)

	return &DummyBarrier{
		IStorage: storage,
		log:      log,
		sealed:   sealed,
	}
}

func (b *DummyBarrier) Unseal(ctx context.Context, key []byte) error {
	b.log.InfoCtx(ctx, "unsealing barrier")
	defer b.log.InfoCtx(ctx, "unsealed barrier")

	b.sealed.Store(false)

	return nil
}

func (b *DummyBarrier) Delete(ctx context.Context, path string) error {
	if b.isSealed() {
		return errors.New("barrier is sealed")
	}

	return b.IStorage.Delete(ctx, path)
}

func (b *DummyBarrier) Update(ctx context.Context, path string, entry secman.Entry, ttl time.Duration) error {
	if b.isSealed() {
		return errors.New("barrier is sealed")
	}

	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("dummy barrier: failed to marshal entry: %w", err)
	}

	return b.IStorage.Update(ctx, path, secman.PhysicalEntry{Value: value}, ttl)
}

var ErrNotFound = errors.New("not found")

func (b *DummyBarrier) Get(ctx context.Context, path string) (secman.Entry, error) {
	if b.isSealed() {
		return secman.Entry{}, errors.New("barrier is sealed")
	}

	res, err := b.IStorage.Get(ctx, path)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("dummy barrier: key %s not found %w", path, ErrNotFound)
	}

	entry := secman.Entry{}
	err = json.Unmarshal(res.Value, &entry)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("dummy barrier: key %s, value %s is not a valid entry: %w", path, string(res.Value), err)
	}

	return entry, nil
}

func (b *DummyBarrier) GetOk(ctx context.Context, path string) (secman.Entry, bool, error) {
	entry, err := b.Get(ctx, path)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return secman.Entry{}, false, nil
		}

		return secman.Entry{}, false, err
	}

	return entry, true, nil
}
func (b *DummyBarrier) isSealed() bool {
	return b.sealed.Load()
}
