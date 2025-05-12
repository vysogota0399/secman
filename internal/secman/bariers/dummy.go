package bariers

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type DummyBarrier struct {
	secman.IStorage
	log        *logging.ZapLogger
	sealed     bool
	sealedLock sync.RWMutex
}

func NewDummyBarrier(storage secman.IStorage, log *logging.ZapLogger) *DummyBarrier {
	return &DummyBarrier{
		IStorage: storage,
		log:      log,
	}
}

func (b *DummyBarrier) Unseal(ctx context.Context, key []byte) error {
	b.log.InfoCtx(ctx, "Unsealing barrier")
	defer b.log.InfoCtx(ctx, "Unsealed barrier")

	return nil
}

func (b *DummyBarrier) Delete(ctx context.Context, path string) error {
	if b.isSealed() {
		return errors.New("barrier is sealed")
	}

	return b.IStorage.Delete(ctx, path)
}

func (b *DummyBarrier) Update(ctx context.Context, path string, entry secman.Entry) error {
	if b.isSealed() {
		return errors.New("barrier is sealed")
	}

	entry.Uuid = []byte(uuid.New().String())

	return b.IStorage.Update(ctx, path, entry)
}

func (b *DummyBarrier) Get(ctx context.Context, path string) (secman.Entry, error) {
	if b.isSealed() {
		return secman.Entry{}, errors.New("barrier is sealed")
	}

	return b.IStorage.Get(ctx, path)
}

func (b *DummyBarrier) isSealed() bool {
	b.sealedLock.RLock()
	defer b.sealedLock.RUnlock()

	return b.sealed
}
