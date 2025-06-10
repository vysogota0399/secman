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

func TestEnableEngine_Handler(t *testing.T) {
	tests := []struct {
		name       string
		enginePath string
		prepare    func(core *secman.Core)
		wantStatus int
	}{
		{
			name:       "engine not found",
			enginePath: "/nonexistent",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve("/nonexistent").Return(nil, assert.AnError)
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "enable engine failed",
			enginePath: "/test",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				mockBackend := secman.NewMockLogicalBackend(gomock.NewController(t))
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve("/test").Return(mockBackend, nil)
				core.Router.(*secman.MockILogicalRouter).EXPECT().EnableEngine(gomock.Any(), mockBackend, gomock.Any()).Return(nil, assert.AnError)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "success",
			enginePath: "/test",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				mockBackend := secman.NewMockLogicalBackend(gomock.NewController(t))
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve("/test").Return(mockBackend, nil)
				core.Router.(*secman.MockILogicalRouter).EXPECT().EnableEngine(gomock.Any(), mockBackend, gomock.Any()).Return(&secman.LogicalResponse{
					Status:  http.StatusOK,
					Message: "engine enabled",
				}, nil)
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

			tt.prepare(core)

			router := NewTestRouter(t, core, nil)

			client, req := NewTestClient(
				context.Background(),
				t,
				core,
				router,
				http.MethodPost,
				"/api/sys/engines/enable"+tt.enginePath,
				nil,
				true,
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
