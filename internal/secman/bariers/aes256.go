package bariers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strconv"
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

func NewPartsBuffer(max int) (*PartsBuffer, error) {
	if max == 0 {
		return nil, errors.New("max must be greater than 0")
	}

	return &PartsBuffer{
		Parts: make([][]byte, 0, max),
		max:   max,
	}, nil
}

func (pb *PartsBuffer) Add(part []byte) bool {
	pb.mtx.Lock()
	defer pb.mtx.Unlock()

	if pb.max == 0 {
		return true
	}

	pb.Parts = append(pb.Parts, part)

	return len(pb.Parts) == pb.max
}

func (pb *PartsBuffer) Clear() {
	pb.mtx.Lock()
	defer pb.mtx.Unlock()

	pb.Parts = make([][]byte, 0, pb.max)
}

type Aes256Barier struct {
	storage                 secman.IStorage
	log                     *logging.ZapLogger
	sealed                  *atomic.Bool
	keyring                 *secman.Keyring
	thresholdsCoundRequired int
	partsCount              int
	partsBuffer             *PartsBuffer
}

var _ secman.IBarrier = &Aes256Barier{}

func NewAes256Barier(storage secman.IStorage, log *logging.ZapLogger, keyring *secman.Keyring) (*Aes256Barier, error) {
	sealed := &atomic.Bool{}
	sealed.Store(true)

	partsCount := 5
	thresholdsCoundRequired := 3

	partsBuffer, err := NewPartsBuffer(thresholdsCoundRequired)
	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: create parts buffer failed error: %w", err)
	}

	return &Aes256Barier{
		storage:                 storage,
		log:                     log,
		sealed:                  sealed,
		keyring:                 keyring,
		thresholdsCoundRequired: thresholdsCoundRequired,
		partsCount:              partsCount,
		partsBuffer:             partsBuffer,
	}, nil
}

func (b *Aes256Barier) Unseal(ctx context.Context, key []byte) (bool, error) {
	b.log.InfoCtx(ctx, "unsealing barrier")
	defer b.log.InfoCtx(ctx, "unsealed barrier")

	if !b.isSealed() {
		return false, errors.New("barrier is already unsealed")
	}

	if !b.partsBuffer.Add(key) {
		return false, nil
	}

	rootKey, err := shamir.Combine(b.partsBuffer.Parts)
	if err != nil {
		b.partsBuffer.Clear()
		return false, fmt.Errorf("aes256 barrier: combine parts failed error: %w", err)
	}

	b.keyring.SetRootKey(&secman.Key{
		Raw:    rootKey,
		Status: secman.KeyStatusActive,
	})

	// preload keys from storage and save them to the keyring
	if err := b.initKeys(); err != nil {
		b.partsBuffer.Clear()
		return false, fmt.Errorf("aes256 barrier: init keys failed error: %w", err)
	}

	b.sealed.Store(false)

	return true, nil
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

	return secman.Entry{Value: string(plaintext), Path: path}, nil
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
			return nil, fmt.Errorf("aes256 barrier: get key %s failed error: %w", path, err)
		}

		plaintext, err := b.decript(pe.Value, key)
		if err != nil {
			return nil, fmt.Errorf("aes256 barrier: decrypt path %s failed error: %w", path, err)
		}

		entries[i] = secman.Entry{Value: string(plaintext), Path: pe.Path}
	}

	return entries, nil
}

func (b *Aes256Barier) isSealed() bool {
	return b.sealed.Load()
}

func (b *Aes256Barier) Info() string {
	return fmt.Sprintf("AES256 SSS keys: %d/%d", len(b.partsBuffer.Parts), b.thresholdsCoundRequired)
}

func (b *Aes256Barier) Init(ctx context.Context) ([][]byte, error) {
	rootKey := b.generateKey()
	backend := b.generateKey()

	// genarate key from bytes, don't put it to the keyring, before unsealing
	backendKey := b.keyring.GenerateKey(backend)

	backendKeyRaw := make([]byte, len(backendKey.Raw)+4)
	binary.BigEndian.PutUint32(backendKeyRaw, backendKey.ID)

	// backend key has such format: [id(4 bytes)][key(32 bytes)]
	copy(backendKeyRaw[4:], backendKey.Raw)

	sealedBackendKey, err := b.encript(
		backendKeyRaw,
		&secman.Key{
			Raw: rootKey,
		},
	)

	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: encrypt backend key failed error: %w", err)
	}

	// split root key into partsw
	thresholds, err := shamir.Split(rootKey, b.partsCount, b.thresholdsCoundRequired)
	if err != nil {
		return nil, fmt.Errorf("aes256 barrier: split backend key failed error: %w", err)
	}

	// save sealed backend key to storage
	if err := b.persistKey(ctx, sealedBackendKey, backendKey.ID); err != nil {
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

	// [id(4 bytes)][nonce(12 bytes)][ciphertext(variable)]
	idLen := 4
	metaLen := idLen + aesgcm.NonceSize()
	totalLen := metaLen + len(message) + aesgcm.Overhead()
	ciphertext := make([]byte, metaLen, totalLen)
	binary.BigEndian.PutUint32(ciphertext, key.ID)
	copy(ciphertext[idLen:], nonce)

	ciphertext = aesgcm.Seal(ciphertext, nonce, message, nil)
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

func (b *Aes256Barier) actualKey() *secman.Key {
	return b.keyring.GetKey(b.keyring.ActualID())
}

func (b *Aes256Barier) keyFromCiphertext(ciphertext []byte) (*secman.Key, error) {
	id := binary.BigEndian.Uint32(ciphertext[:4])
	key := b.keyring.GetKey(id)

	if key == nil {
		return nil, fmt.Errorf("aes256 barrier: key %d not found", id)
	}

	return key, nil
}

func (b *Aes256Barier) persistKey(ctx context.Context, key []byte, id uint32) error {
	return b.storage.Update(ctx, path.Join(secman.KeyringPath, strconv.Itoa(int(id))), secman.PhysicalEntry{Value: key}, 0)
}

func (b *Aes256Barier) initKeys() error {
	keys, err := b.storage.List(context.Background(), secman.KeyringPath)
	if err != nil {
		return fmt.Errorf("aes256 barrier: list keys failed error: %w", err)
	}

	for _, key := range keys {
		decryptedKey, err := b.decript(key.Value, b.keyring.RootKey)
		if err != nil {
			return fmt.Errorf("aes256 barrier: decrypt key failed error: %w", err)
		}

		b.keyring.AddKey(decryptedKey[4:], binary.BigEndian.Uint32(decryptedKey))
	}

	return nil
}

func (b *Aes256Barier) generateKey() []byte {
	// generate 32 bytes key block for AES256
	return cryptoutils.GenerateRandom(aes.BlockSize * 2)
}
