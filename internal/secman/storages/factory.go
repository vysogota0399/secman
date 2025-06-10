package storages

import (
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/config"
)

func NewStorage(config *config.Config, lg *logging.ZapLogger) (secman.IStorage, error) {
	storageType, ok := config.Storage["type"].(string)
	if !ok {
		return nil, fmt.Errorf("initialize storage failed: type cast error for storage - got %T expected string", config.Storage["type"])
	}

	switch storageType {
	case "redis":
		redisConfig, err := newRedisConfig(config.Storage)
		if err != nil {
			return nil, err
		}
		return newRedisStorage(lg, redisConfig), nil
	default:
		return nil, fmt.Errorf("storage %s not found", storageType)
	}
}
