package secman

import (
	"context"
	"time"
)

// IBarrier is an interface that defines the methods for a barrier. When the barrier is sealed, the storage is not accessible.
// To unseal the barrier, the secret key is needed.
// - Unseal is a method that unseals the barrier
type IBarrier interface {
	Get(ctx context.Context, path string) (Entry, error)
	GetOk(ctx context.Context, path string) (Entry, bool, error)
	Update(ctx context.Context, path string, value Entry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
	Unseal(ctx context.Context, key []byte) error
	List(ctx context.Context, path string) ([]Entry, error)
}

type Entry struct {
	Path  string `json:"path"`
	Value string `json:"value"`
}
