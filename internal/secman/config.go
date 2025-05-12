package secman

import (
	"github.com/caarlos0/env"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	LogLevel int            `env:"LOG_LEVEL" default:"-1" json:"log_level"`
	Address  string         `env:"ADDRESS" default:"0.0.0.0:8080" json:"address"`
	Auth     map[string]any `json:"auth"`
	Storage  map[string]any `json:"storage"`
}

func NewConfig() *Config {
	cfg := &Config{
		LogLevel: -1,
	}

	if err := env.Parse(cfg); err != nil {
		panic(err)
	}

	return cfg
}

func (c *Config) LLevel() zapcore.Level {
	return zapcore.Level(c.LogLevel)
}
