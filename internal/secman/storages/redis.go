package storages

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type RedisStorage struct {
	lg  *logging.ZapLogger
	rdb *redis.Client
}

var _ secman.IStorage = &RedisStorage{}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

func newRedisConfig(config map[string]any) (RedisConfig, error) {
	host, ok := config["host"].(string)
	if !ok {
		return RedisConfig{}, fmt.Errorf("initialize storage failed: type cast error for host - got %T expected string", config["host"])
	}

	password, ok := config["password"].(string)
	if !ok {
		return RedisConfig{}, fmt.Errorf("initialize storage failed: type cast error for password - got %T expected string", config["password"])
	}

	db, ok := config["db"].(int)
	if !ok {
		return RedisConfig{}, fmt.Errorf("initialize storage failed: type cast error for db - got %T expected int", config["db"])
	}

	return RedisConfig{
		Addr:     host,
		Password: password,
		DB:       db,
	}, nil
}

func newRedisStorage(lg *logging.ZapLogger, config RedisConfig) *RedisStorage {
	return &RedisStorage{
		lg: lg,
		rdb: redis.NewClient(&redis.Options{
			Addr:     config.Addr,
			Password: config.Password,
			DB:       config.DB,
		}),
	}
}

func (s *RedisStorage) Get(ctx context.Context, path string) (secman.PhysicalEntry, error) {
	record := s.rdb.Get(ctx, path)
	if record.Err() == redis.Nil {
		return secman.PhysicalEntry{}, secman.ErrEntryNotFound
	}

	res, err := record.Bytes()
	if err != nil {
		return secman.PhysicalEntry{}, fmt.Errorf("storage: failed to get entry with key %s: %w", path, err)
	}

	return secman.PhysicalEntry{Value: res}, nil
}

func (s *RedisStorage) Update(ctx context.Context, path string, entry secman.PhysicalEntry, ttl time.Duration) error {
	return s.rdb.Set(ctx, path, entry.Value, ttl).Err()
}

func (s *RedisStorage) Delete(ctx context.Context, path string) error {
	return nil
}
