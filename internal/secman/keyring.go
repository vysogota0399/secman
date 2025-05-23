package secman

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sync"
)

type Keyring struct {
	keyMtx  sync.RWMutex
	RootKey *Key
	Keys    map[string]map[int]*Key
}

func NewKeyring() *Keyring {
	return &Keyring{
		Keys:   make(map[string]map[int]*Key),
		keyMtx: sync.RWMutex{},
	}
}

func (k *Keyring) GetKey(name string, version int) *Key {
	k.keyMtx.RLock()
	defer k.keyMtx.RUnlock()

	if k.Keys[name] == nil {
		return nil
	}

	return k.Keys[name][version]
}

func (kr *Keyring) GenerateKey(name string) (*Key, error) {
	kr.keyMtx.Lock()
	defer kr.keyMtx.Unlock()

	var version int

	if _, ok := kr.Keys[name]; !ok {
		version = 1
	} else {
		version = len(kr.Keys[name]) + 1
	}

	k, err := generateRandom(aes.BlockSize * 2)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce, err := generateRandom(aesgcm.NonceSize())
	if err != nil {
		return nil, err
	}

	key := &Key{
		Name:    name,
		Version: version,
		block:   block,
		aesgcm:  aesgcm,
		nonce:   nonce,
		Status:  KeyStatusActive,
	}

	kr.Keys[name][version] = key

	return key, nil
}

type Key struct {
	Name    string
	Version int
	block   cipher.Block
	aesgcm  cipher.AEAD
	Status  KeyStatus
	nonce   []byte
}

type KeyStatus int

const (
	KeyStatusActive KeyStatus = iota
	KeyStatusInactive
)

func (k *Key) Seal(data []byte) ([]byte, error) {
	return k.aesgcm.Seal(nil, k.nonce, data, nil), nil
}

func (k *Key) Unseal(data []byte) ([]byte, error) {
	return k.aesgcm.Open(nil, k.nonce, data, nil)
}

func generateRandom(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}
