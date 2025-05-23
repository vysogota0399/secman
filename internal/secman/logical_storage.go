package secman

import (
	"context"
	"path"
	"time"
)

type ILogicalStorage interface {
	Get(ctx context.Context, path string) (Entry, error)
	GetOk(ctx context.Context, path string) (Entry, bool, error)
	Update(ctx context.Context, path string, value Entry, ttl time.Duration) error
	Delete(ctx context.Context, path string) error
	List(ctx context.Context, path string) ([]Entry, error)
	Prefix() string
}

type LogicalStorage struct {
	b      BarrierStorage
	prefix string
}

func (s *LogicalStorage) Prefix() string {
	return s.prefix
}

var _ ILogicalStorage = &LogicalStorage{}

func NewLogicalStorage(b BarrierStorage, path string) *LogicalStorage {
	return &LogicalStorage{b: b, prefix: path}
}

func (s *LogicalStorage) Get(ctx context.Context, path string) (Entry, error) {
	return s.b.Get(ctx, s.relativePath(path))
}

func (s *LogicalStorage) GetOk(ctx context.Context, path string) (Entry, bool, error) {
	return s.b.GetOk(ctx, s.relativePath(path))
}

func (s *LogicalStorage) Update(ctx context.Context, path string, value Entry, ttl time.Duration) error {
	return s.b.Update(ctx, s.relativePath(path), value, ttl)
}

func (s *LogicalStorage) Delete(ctx context.Context, path string) error {
	return s.b.Delete(ctx, s.relativePath(path))
}

func (s *LogicalStorage) List(ctx context.Context, path string) ([]Entry, error) {
	return s.b.List(ctx, s.relativePath(path))
}

func (s *LogicalStorage) relativePath(p string) string {
	return path.Join(s.prefix, p)
}
