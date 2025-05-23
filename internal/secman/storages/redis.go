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
	return s.rdb.Del(ctx, path).Err()
}

func (s *RedisStorage) List(ctx context.Context, path string) ([]secman.PhysicalEntry, error) {
	var entries []secman.PhysicalEntry
	var cursor uint64
	var err error

	for {
		var keys []string
		keys, cursor, err = s.rdb.Scan(ctx, cursor, path+"*", 10).Result()
		if err != nil {
			return nil, fmt.Errorf("storage: failed to scan keys: %w", err)
		}

		if len(keys) > 0 {
			// Use pipeline for better performance
			pipe := s.rdb.Pipeline()
			cmds := make([]*redis.StringCmd, len(keys))

			for i, key := range keys {
				cmds[i] = pipe.Get(ctx, key)
			}

			_, err = pipe.Exec(ctx)
			if err != nil && err != redis.Nil {
				return nil, fmt.Errorf("storage: failed to get values: %w", err)
			}

			// Process results
			for i, cmd := range cmds {
				val, err := cmd.Bytes()
				if err == nil {
					entries = append(entries, secman.PhysicalEntry{Value: val, Key: keys[i]})
				}
			}
		}

		if cursor == 0 {
			break
		}
	}

	return entries, nil
}
