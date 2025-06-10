package secman

import (
	"context"
	"time"
)

// IBarrier is an interface that defines the methods for a barrier. When the barrier is sealed, the storage is not accessible.
// To unseal the barrier, the secret key is needed.
// - Unseal is a method that unseals the barrier
type IBarrier interface {
	BarrierStorage
	// Init initializes the barrier with root key
	Init(ctx context.Context) ([][]byte, error)
	// Unseal unseals the barrier with the given key
	// Returns true if the barrier is unsealed, false if error occurred or berier is still sealed
	Unseal(ctx context.Context, key []byte) (bool, error)
	Info() string
}

type BarrierStorage interface {
	Get(ctx context.Context, path string) (Entry, error)
	GetOk(ctx context.Context, path string) (Entry, bool, error)
	Update(ctx context.Context, path string, value Entry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, path string) ([]Entry, error)
}

type Entry struct {
	// Key is the logical key of the entry
	Key string `json:"key"`
	// Path is the physical path of the entry in the storage
	Path  string `json:"path"`
	Value string `json:"value"`
}
