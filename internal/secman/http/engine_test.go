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

func TestEngine_Handler(t *testing.T) {
	tests := []struct {
		name       string
		wantStatus int
		prepare    func(core *secman.Core)
	}{
		{
			name:       "error resolve engine",
			wantStatus: http.StatusNotFound,
			prepare: func(core *secman.Core) {
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve(gomock.Any()).Return(nil, assert.AnError)
			},
		},
		{
			name:       "path not found",
			wantStatus: http.StatusNotFound,
			prepare: func(core *secman.Core) {
				be := secman.NewMockLogicalBackend(gomock.NewController(t))
				be.EXPECT().Paths().Return(map[string]map[string]*secman.Path{})

				backendRouter, err := secman.NewBackendRouter(be, secman.NewLogger(t))
				if err != nil {
					t.Fatalf("Failed to create backend router: %v", err)
				}

				engine := secman.NewMockLogicalBackend(gomock.NewController(t))
				engine.EXPECT().Router().Return(backendRouter)

				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve(gomock.Any()).Return(engine, nil)
			},
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

			core.IsSealed.Store(false)
			tt.prepare(core)

			router := NewTestRouter(t, core, nil)

			client, req := NewTestClient(
				context.Background(),
				t,
				core,
				router,
				http.MethodPost,
				"/api/engine/test",
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
