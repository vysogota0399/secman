package bariers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/cryptoutils"
	"go.bryk.io/pkg/crypto/shamir"
)

type PartsBuffer struct {
	Parts [][]byte
	mtx   sync.RWMutex
	max   int
}

func NewPartsBuffer(max int) *PartsBuffer {
	return &PartsBuffer{
		Parts: make([][]byte, 0, max),
		max:   max,
	}
}

func (pb *PartsBuffer) Add(part []byte) bool {
	pb.mtx.Lock()
	defer pb.mtx.Unlock()

	pb.Parts = append(pb.Parts, part)

	return len(pb.Parts) == pb.max
}

func (pb *PartsBuffer) Clear() {
	pb.mtx.Lock()
	defer pb.mtx.Unlock()

	pb.Parts = make([][]byte, 0, pb.max)
}

type Aes256Barier struct {
	storage            secman.IStorage
	log                *logging.ZapLogger
	sealed             *atomic.Bool
	keyring            *secman.Keyring
	thresholdsCount    int
	partsCountRequired int
	partsBuffer        *PartsBuffer
}

var _ secman.IBarrier = &Aes256Barier{}

func NewAes256Barier(storage secman.IStorage, log *logging.ZapLogger, keyring *secman.Keyring) *Aes256Barier {
	sealed := &atomic.Bool{}
	sealed.Store(true)

	partsCountRequired := 5
	thresholdsCount := 3

	return &Aes256Barier{
		storage:            storage,
		log:                log,
		sealed:             sealed,
		keyring:            keyring,
		thresholdsCount:    thresholdsCount,
		partsCountRequired: partsCountRequired,
		partsBuffer:        NewPartsBuffer(partsCountRequired),
	}
}

func (b *Aes256Barier) Unseal(ctx context.Context, key []byte) error {
	b.log.InfoCtx(ctx, "unsealing barrier")
	defer b.log.InfoCtx(ctx, "unsealed barrier")

	if !b.partsBuffer.Add(key) {
		return nil
	}

	rootKey, err := shamir.Combine(b.partsBuffer.Parts)
	if err != nil {
		b.partsBuffer.Clear()
		return fmt.Errorf("aes256 barrier: combine parts failed error: %w", err)
	}

	b.keyring.SetRootKey(&secman.Key{
		ID:     1,
		Raw:    rootKey,
		Status: secman.KeyStatusActive,
	})

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

	ciphertext, err := b.encript([]byte(entry.Value), b.actualKey())
	if err != nil {
		return fmt.Errorf("aes256 barrier: encrypt path %s failed error: %w", path, err)
	}

	return b.storage.Update(ctx, path, secman.PhysicalEntry{Value: ciphertext}, ttl)
}

func (b *Aes256Barier) Get(ctx context.Context, path string) (secman.Entry, error) {
	if b.isSealed() {
		return secman.Entry{}, errors.New("barrier is sealed")
	}

	res, err := b.storage.Get(ctx, path)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("aes256 barrier: get key %s failed error: %w", path, err)
	}

	key, err := b.keyFromCiphertext(res.Value)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("aes256 barrier: get key %s failed error: %w", path, err)
	}

	plaintext, err := b.decript(res.Value, key)
	if err != nil {
		return secman.Entry{}, fmt.Errorf("aes256 barrier: decrypt key %s failed error: %w", path, err)
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
		key, err := b.keyFromCiphertext(pe.Value)
		if err != nil {
			return nil, fmt.Errorf("aes256 barrier: get key %s failed error: %w", pe.Key, err)
		}

		plaintext, err := b.decript(pe.Value, key)
		if err != nil {
			return nil, fmt.Errorf("aes256 barrier: decrypt path %s failed error: %w", pe.Key, err)
		}

		entries[i] = secman.Entry{Value: string(plaintext)}
	}

	return entries, nil
}

func (b *Aes256Barier) isSealed() bool {
	return b.sealed.Load()
}

func (b *Aes256Barier) Info() string {
	return fmt.Sprintf("AES256 SSS keys: %d/%d", len(b.partsBuffer.Parts), b.partsCountRequired)
}

func (b *Aes256Barier) Init(ctx context.Context) ([][]byte, error) {
	rootKey, err := b.keyring.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: generate master key failed error: %w", err)
	}
	backendKey, err := b.keyring.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: generate backend key failed error: %w", err)
	}

	sealedBackendKey, err := b.encript(backendKey.Raw, rootKey)
	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: encrypt backend key failed error: %w", err)
	}

	thresholds, err := shamir.Split(backendKey.Raw, b.partsCountRequired, b.thresholdsCount)
	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: split backend key failed error: %w", err)
	}

	b.keyring.AddKey(backendKey)

	if err := b.persistKey(ctx, sealedBackendKey); err != nil {
		return nil, fmt.Errorf("aes256 barrier: persist root backend key failed error: %w", err)
	}

	return thresholds, nil
}

func (b *Aes256Barier) encript(message []byte, key *secman.Key) ([]byte, error) {
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

	binary.BigEndian.PutUint32(ciphertext[:4], key.ID)
	copy(ciphertext[4:], nonce)
	aesgcm.Seal(ciphertext[4+aesgcm.NonceSize():], nonce, message, nil)

	return ciphertext, nil
}

func (b *Aes256Barier) decript(message []byte, key *secman.Key) ([]byte, error) {
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

func (a *Aes256Barier) actualKey() *secman.Key {
	return a.keyring.GetKey(a.keyring.ActualID())
}

func (b *Aes256Barier) keyFromCiphertext(ciphertext []byte) (*secman.Key, error) {
	id := binary.BigEndian.Uint32(ciphertext[:4])
	key := b.keyring.GetKey(id)

	if key == nil {
		return nil, fmt.Errorf("aes256 barrier: key %d not found", id)
	}

	return key, nil
}

func (b *Aes256Barier) persistKey(ctx context.Context, key []byte) error {
	return b.storage.Update(ctx, path.Join(secman.KeyringPath, string(key[:4])), secman.PhysicalEntry{Value: key}, 0)
}
