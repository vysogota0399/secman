package storages

import (
	"context"

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

func newRedisConfig(config map[string]any) RedisConfig {
	return RedisConfig{
		Addr:     config["addr"].(string),
		Password: config["password"].(string),
		DB:       config["db"].(int),
	}
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

func (s *RedisStorage) Get(ctx context.Context, path string) (secman.Entry, error) {
	return secman.Entry{}, nil
}

func (s *RedisStorage) Update(ctx context.Context, path string, value secman.Entry) error {
	return nil
}

func (s *RedisStorage) Delete(ctx context.Context, path string) error {
	return nil
}
