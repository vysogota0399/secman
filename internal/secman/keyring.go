package secman

import (
	"crypto/aes"
	"sync"
	"sync/atomic"

	"github.com/vysogota0399/secman/internal/secman/cryptoutils"
)

type Keyring struct {
	keyMtx   sync.RWMutex
	RootKey  *Key
	actualID uint32
	Keys     map[uint32]*Key
}

func NewKeyring() *Keyring {
	return &Keyring{
		Keys:     make(map[uint32]*Key),
		keyMtx:   sync.RWMutex{},
		actualID: 0,
	}
}

func (kr *Keyring) ActualID() uint32 {
	kr.keyMtx.RLock()
	defer kr.keyMtx.RUnlock()

	return kr.actualID
}

func (k *Keyring) GetKey(id uint32) *Key {
	k.keyMtx.RLock()
	defer k.keyMtx.RUnlock()

	if k.Keys[id] == nil {
		return nil
	}

	return k.Keys[id]
}

func (kr *Keyring) GenerateKey() (*Key, error) {
	kr.keyMtx.Lock()
	defer kr.keyMtx.Unlock()

	k := cryptoutils.GenerateRandom(aes.BlockSize * 2)
	id := atomic.AddUint32(&kr.actualID, 1)

	key := &Key{
		ID:     id,
		Raw:    k,
		Status: KeyStatusActive,
	}

	kr.Keys[id] = key

	return key, nil
}

type Key struct {
	ID     uint32
	Raw    []byte
	Status KeyStatus
}

type KeyStatus int

const (
	KeyStatusActive KeyStatus = iota
	KeyStatusInactive
)
