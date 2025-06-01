package cli

import (
	"github.com/caarlos0/env"
	"go.uber.org/zap/zapcore"
)

type Config struct {
	ServerURL     string `env:"SERVER_URL"`
	RootToken     string `env:"ROOT_TOKEN" envDefault:""`
	LogLevel      int64  `env:"LOG_LEVEL" envDefault:"0"`
	SSLSkipVerify bool   `env:"SSL_SKIP_VERIFY" envDefault:"false"`
}

func NewConfig() (*Config, error) {
	c := &Config{}
	if err := env.Parse(c); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Config) LLevel() zapcore.Level {
	return zapcore.Level(c.LogLevel)
}
