package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/config"
)

func TestEnableEngine_Handler(t *testing.T) {
	tests := []struct {
		name       string
		enginePath string
		prepare    func(core *server.Core)
		wantStatus int
	}{
		{
			name:       "engine not found",
			enginePath: "/nonexistent",
			prepare: func(core *server.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				core.Router.(*server.MockILogicalRouter).EXPECT().Resolve("/nonexistent").Return(nil, assert.AnError)
			},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "enable engine failed",
			enginePath: "/test",
			prepare: func(core *server.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				mockBackend := server.NewMockLogicalBackend(gomock.NewController(t))
				core.Router.(*server.MockILogicalRouter).EXPECT().Resolve("/test").Return(mockBackend, nil)
				core.Router.(*server.MockILogicalRouter).EXPECT().EnableEngine(gomock.Any(), mockBackend, gomock.Any()).Return(nil, assert.AnError)
			},
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "success",
			enginePath: "/test",
			prepare: func(core *server.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				mockBackend := server.NewMockLogicalBackend(gomock.NewController(t))
				core.Router.(*server.MockILogicalRouter).EXPECT().Resolve("/test").Return(mockBackend, nil)
				core.Router.(*server.MockILogicalRouter).EXPECT().EnableEngine(gomock.Any(), mockBackend, gomock.Any()).Return(&server.LogicalResponse{
					Status:  http.StatusOK,
					Message: "engine enabled",
				}, nil)
			},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, app := server.NewTestCore(t, &config.Config{
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
