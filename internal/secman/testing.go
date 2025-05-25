package secman

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
)

func NewController(t *testing.T) *gomock.Controller {
	t.Helper()

	ctrl := gomock.NewController(t)

	t.Cleanup(func() {
		ctrl.Finish()
	})

	return ctrl
}

func NewLogger(t *testing.T) *logging.ZapLogger {
	t.Helper()

	lg, err := logging.MustZapLogger(&config.Config{LogLevel: -1})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	return lg
}
