package secman

import (
	"sync"
	"sync/atomic"
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

func (kr *Keyring) GetKey(id uint32) *Key {
	kr.keyMtx.RLock()
	defer kr.keyMtx.RUnlock()

	if kr.Keys[id] == nil {
		return nil
	}

	return kr.Keys[id]
}

func (kr *Keyring) SetRootKey(key *Key) {
	kr.keyMtx.Lock()
	defer kr.keyMtx.Unlock()

	kr.RootKey = key
}

// AddKey add key to keyring. Assumes that key is already generated.
func (kr *Keyring) AddKey(key []byte, id uint32) *Key {
	kr.keyMtx.Lock()
	defer kr.keyMtx.Unlock()

	k := &Key{
		ID:     id,
		Raw:    key,
		Status: KeyStatusActive,
	}

	kr.Keys[id] = k

	kr.actualizeActualID()

	return k
}

// GenerateKey process key rotation. Mark previous key as inactive.
// It should not save key to keyring. To save key to keyring use AddKey.
func (kr *Keyring) GenerateKey(b []byte) *Key {
	kr.keyMtx.Lock()
	defer kr.keyMtx.Unlock()

	// mark previous key as inactive if it exists
	prevKey := kr.Keys[kr.actualID]
	if prevKey != nil {
		prevKey.Status = KeyStatusInactive
	}

	atomic.AddUint32(&kr.actualID, 1)

	k := &Key{
		ID:     kr.actualID,
		Raw:    b,
		Status: KeyStatusActive,
	}

	return k
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

func (kr *Keyring) actualizeActualID() {
	maxID := uint32(0)
	for id, key := range kr.Keys {
		if key.Status == KeyStatusActive && id > maxID {
			maxID = id
		}
	}

	kr.actualID = maxID
}
