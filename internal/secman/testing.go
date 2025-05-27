package secman

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman/config"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
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

func NewTestCore(t *testing.T, config *config.Config, isCoreInitialized bool) (*Core, *fxtest.App) {
	t.Helper()

	cnt := NewController(t)

	mockBarrier := NewMockIBarrier(cnt)
	mockCoreRepository := NewMockICoreRepository(cnt)
	mockRouter := NewMockILogicalRouter(cnt)
	mockAuth := NewMockIAuth(cnt)
	mockRootTokens := NewMockIRootTokens(cnt)

	var (
		l fx.Lifecycle
		s fx.Shutdowner
	)

	app := fxtest.New(
		t,
		fx.Populate(&l, &s),
	)

	t.Cleanup(func() {
		err := app.Stop(context.Background())
		if err != nil {
			t.Fatalf("failed to stop app: %v", err)
		}
	})

	mockCoreRepository.EXPECT().IsCoreInitialized(context.Background()).Return(isCoreInitialized, nil)

	return NewCore(
		mockBarrier,
		l,
		NewLogger(t),
		config,
		mockCoreRepository,
		mockRootTokens,
		mockRouter,
		mockAuth,
	), app
}
