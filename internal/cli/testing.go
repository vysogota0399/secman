package cli

import (
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap/zapcore"
)

func NewController(t *testing.T) *gomock.Controller {
	t.Helper()

	ctrl := gomock.NewController(t)

	t.Cleanup(func() {
		ctrl.Finish()
	})

	return ctrl
}

type TestConfig struct {
	LogLevel int
}

func (c *TestConfig) LLevel() zapcore.Level {
	return zapcore.Level(c.LogLevel)
}

func NewLogger(t *testing.T) *logging.ZapLogger {
	t.Helper()

	lg, err := logging.MustZapLogger(&TestConfig{LogLevel: -1})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	return lg
}
