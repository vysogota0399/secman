package config

import (
	"os"

	"github.com/caarlos0/env"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	FileStoragePath string         `env:"FILE_STORAGE_PATH"`
	LogLevel        int            `yml:"log_level" env:"LOG_LEVEL"`
	Server          Server         `yml:"server"`
	Storage         map[string]any `yml:"storage"`
}

type Server struct {
	Address string `yml:"address"`
}

func NewConfig() (*Config, error) {
	cfg := &Config{}

	if path, ok := os.LookupEnv("FILE_STORAGE_PATH"); ok {
		cfg.FileStoragePath = path
	} else {
		cfg.FileStoragePath = "config.yml"
	}

	if err := parseYML(cfg); err != nil {
		return nil, err
	}

	if err := env.Parse(cfg); err != nil {
		return nil, err
	}

	cfg.LogLevel = -1
	return cfg, nil
}

func (c *Config) LLevel() zapcore.Level {
	return zapcore.Level(c.LogLevel)
}
