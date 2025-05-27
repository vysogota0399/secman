package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/config"
)

func TestInit_Handler(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(core *secman.Core, coreRepository *secman.MockICoreRepository)
		wantStatus int
	}{
		{
			name: "already initialized",
			prepare: func(core *secman.Core, coreRepository *secman.MockICoreRepository) {
				core.IsInitialized.Store(true)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "init root token failed",
			prepare: func(core *secman.Core, coreRepository *secman.MockICoreRepository) {
				core.IsInitialized.Store(false)
				core.RootTokens.(*secman.MockIRootTokens).EXPECT().Gen(gomock.Any(), gomock.Any()).Return("", assert.AnError)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "init barrier failed",
			prepare: func(core *secman.Core, coreRepository *secman.MockICoreRepository) {
				core.IsInitialized.Store(false)
				core.RootTokens.(*secman.MockIRootTokens).EXPECT().Gen(gomock.Any(), gomock.Any()).Return("root-token", nil)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Init(gomock.Any()).Return(nil, assert.AnError)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "init core failed",
			prepare: func(core *secman.Core, coreRepository *secman.MockICoreRepository) {
				core.IsInitialized.Store(false)
				core.RootTokens.(*secman.MockIRootTokens).EXPECT().Gen(gomock.Any(), gomock.Any()).Return("root-token", nil)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Init(gomock.Any()).Return([][]byte{[]byte("unseal-token")}, nil)
				coreRepository.EXPECT().SetCoreInitialized(gomock.Any(), true).Return(assert.AnError)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			prepare: func(core *secman.Core, coreRepository *secman.MockICoreRepository) {
				core.IsInitialized.Store(false)
				core.RootTokens.(*secman.MockIRootTokens).EXPECT().Gen(gomock.Any(), gomock.Any()).Return("root-token", nil)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Init(gomock.Any()).Return([][]byte{[]byte("unseal-token")}, nil)
				coreRepository.EXPECT().SetCoreInitialized(gomock.Any(), true).Return(nil)
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, app := secman.NewTestCore(t, &config.Config{
				Server: config.Server{
					Address: "localhost:8080",
				},
			}, true)
			if err := app.Start(context.Background()); err != nil {
				t.Fatalf("Failed to start app: %v", err)
			}

			coreRepository := secman.NewMockICoreRepository(gomock.NewController(t))
			tt.prepare(core, coreRepository)

			router := NewTestRouter(t, core, coreRepository)

			client, req := NewTestClient(
				context.Background(),
				t,
				core,
				router,
				http.MethodPost,
				"/api/sys/init",
				nil,
				false,
			)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Failed to do request: %v", err)
			}
			defer resp.Body.Close()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)
		})
	}
}
