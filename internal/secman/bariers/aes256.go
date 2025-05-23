package bariers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/cryptoutils"
)

type Aes256Barier struct {
	storage secman.IStorage
	log     *logging.ZapLogger
	sealed  *atomic.Bool
	keyring *secman.Keyring
}

var _ secman.IBarrier = &Aes256Barier{}

func NewAes256Barier(storage secman.IStorage, log *logging.ZapLogger, keyring *secman.Keyring) *Aes256Barier {
	sealed := &atomic.Bool{}
	sealed.Store(true)

	return &Aes256Barier{
		storage: storage,
		log:     log,
		sealed:  sealed,
		keyring: keyring,
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

	ciphertext, err := b.encript([]byte(entry.Value))
	if err != nil {
		return fmt.Errorf("dummy barrier: encrypt path %s failed error: %w", path, err)
	}

	return b.storage.Update(ctx, path, secman.PhysicalEntry{Value: ciphertext}, ttl)
}

func (b *Aes256Barier) Get(ctx context.Context, path string) (secman.Entry, error) {
	if b.isSealed() {
		return secman.Entry{}, errors.New("barrier is sealed")
	}

	res, err := b.storage.Get(ctx, path)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("dummy barrier: get key %s failed error: %w", path, err)
	}

	plaintext, err := b.decript(res.Value)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("dummy barrier: decrypt key %s failed error: %w", path, err)
	}

	return secman.Entry{Value: string(plaintext)}, nil
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
		plaintext, err := b.decript(pe.Value)
		if err != nil {
			return nil, fmt.Errorf("dummy barrier: decrypt path %s failed error: %w", pe.Key, err)
		}

		entries[i] = secman.Entry{Value: string(plaintext)}
	}

	return entries, nil
}

func (b *Aes256Barier) isSealed() bool {
	return b.sealed.Load()
}

func (b *Aes256Barier) Init(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (b *Aes256Barier) encript(message []byte) ([]byte, error) {
	id := b.keyring.ActualID()
	key := b.keyring.GetKey(id)

	block, err := aes.NewCipher(key.Raw)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := cryptoutils.GenerateRandom(aesgcm.NonceSize())

	ciphertext := make([]byte, 4+aesgcm.NonceSize()+len(message)+aesgcm.Overhead())

	binary.BigEndian.PutUint32(ciphertext[:4], id)
	copy(ciphertext[4:], nonce)
	aesgcm.Seal(ciphertext[4+aesgcm.NonceSize():], nonce, message, nil)

	return ciphertext, nil
}

func (b *Aes256Barier) decript(message []byte) ([]byte, error) {
	id := binary.BigEndian.Uint32(message[:4])
	key := b.keyring.GetKey(id)

	block, err := aes.NewCipher(key.Raw)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := message[4 : 4+aesgcm.NonceSize()]

	plaintext, err := aesgcm.Open(nil, nonce, message[4+aesgcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
