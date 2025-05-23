package bariers

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type Aes256Barier struct {
	storage secman.IStorage
	log     *logging.ZapLogger
	sealed  *atomic.Bool
}

var _ secman.IBarrier = &Aes256Barier{}

func NewAes256Barier(storage secman.IStorage, log *logging.ZapLogger) *Aes256Barier {
	sealed := &atomic.Bool{}
	sealed.Store(true)

	return &Aes256Barier{
		storage: storage,
		log:     log,
		sealed:  sealed,
	}
}

func (b *Aes256Barier) Unseal(ctx context.Context, key []byte) error {
	b.log.InfoCtx(ctx, "unsealing barrier")
	defer b.log.InfoCtx(ctx, "unsealed barrier")

	b.sealed.Store(false)

	return nil
}

func (b *Aes256Barier) Delete(ctx context.Context, path string) error {
	if b.isSealed() {
		return errors.New("barrier is sealed")
	}

	return b.storage.Delete(ctx, path)
}

func (b *Aes256Barier) Update(ctx context.Context, path string, entry secman.Entry, ttl time.Duration) error {
	if b.isSealed() {
		return errors.New("barrier is sealed")
	}

	return b.storage.Update(ctx, path, secman.PhysicalEntry{Value: []byte(entry.Value)}, ttl)
}

func (b *Aes256Barier) Get(ctx context.Context, path string) (secman.Entry, error) {
	if b.isSealed() {
		return secman.Entry{}, errors.New("barrier is sealed")
	}

	res, err := b.storage.Get(ctx, path)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("dummy barrier: get key %s failed error: %w", path, err)
	}

	return secman.Entry{Value: string(res.Value), Key: res.Key}, nil
}

func (b *Aes256Barier) GetOk(ctx context.Context, path string) (secman.Entry, bool, error) {
	entry, err := b.Get(ctx, path)
	if err != nil {
		if errors.Is(err, secman.ErrEntryNotFound) {
			return secman.Entry{}, false, nil
		}

		return secman.Entry{}, false, err
	}

	return entry, true, nil
}

func (b *Aes256Barier) List(ctx context.Context, path string) ([]secman.Entry, error) {
	if b.isSealed() {
		return nil, errors.New("barrier is sealed")
	}

	physicalEntries, err := b.storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	entries := make([]secman.Entry, len(physicalEntries))
	for i, pe := range physicalEntries {
		entries[i] = secman.Entry{Value: string(pe.Value), Key: pe.Key}
	}

	return entries, nil
}

func (b *Aes256Barier) isSealed() bool {
	return b.sealed.Load()
}

func (b *Aes256Barier) Init(ctx context.Context) ([]byte, error) {
	return nil, nil
}
