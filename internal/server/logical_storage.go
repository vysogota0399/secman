package server

import (
	"context"
	"path"
	"strings"
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
	entry, err := s.b.Get(ctx, s.relativePath(path))
	if err != nil {
		return Entry{}, err
	}

	entry.Key = strings.TrimPrefix(entry.Path, s.prefix)
	return entry, nil
}

func (s *LogicalStorage) GetOk(ctx context.Context, key string) (Entry, bool, error) {
	return s.b.GetOk(ctx, s.relativePath(key))
}

func (s *LogicalStorage) Update(ctx context.Context, key string, value Entry, ttl time.Duration) error {
	return s.b.Update(ctx, s.relativePath(key), value, ttl)
}

func (s *LogicalStorage) Delete(ctx context.Context, key string) error {
	return s.b.Delete(ctx, s.relativePath(key))
}

func (s *LogicalStorage) List(ctx context.Context, key string) ([]Entry, error) {
	entries, err := s.b.List(ctx, s.relativePath(key))
	if err != nil {
		return nil, err
	}

	for i, entry := range entries {
		entries[i] = Entry{
			Value: entry.Value,
			Key:   strings.TrimPrefix(entry.Path, s.prefix),
			Path:  entry.Path,
		}
	}

	return entries, nil
}

func (s *LogicalStorage) relativePath(p string) string {
	res := path.Join(s.prefix, p)
	if strings.HasSuffix(p, "/") {
		return res + "/"
	}

	return res
}
