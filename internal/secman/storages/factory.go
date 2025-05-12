package storages

import (
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

func NewStorage(storageType string, config secman.Config, lg *logging.ZapLogger) (secman.IStorage, error) {
	cfg := config.Storage
	switch storageType {
	case "redis":
		return newRedisStorage(lg, newRedisConfig(cfg)), nil
	default:
		return nil, fmt.Errorf("storage %s not found", storageType)
	}
}
