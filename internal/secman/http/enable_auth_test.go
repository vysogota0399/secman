package http

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/config"
)

func TestEnableAuth_Handler(t *testing.T) {
	tests := []struct {
		name       string
		body       io.Reader
		prepare    func(core *secman.Core)
		wantStatus int
	}{
		{
			name: "error invalid body",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
			},
			body:       strings.NewReader("invalid"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "engine not found",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve("/nonexistent").Return(nil, assert.AnError)
			},
			body:       strings.NewReader("{\"engine_path\": \"/nonexistent\"}"),
			wantStatus: http.StatusNotFound,
		},
		{
			name: "enable auth failed",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				mockBackend := secman.NewMockLogicalBackend(gomock.NewController(t))
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve("/test").Return(mockBackend, nil)
				core.Auth.(*secman.MockIAuth).EXPECT().EnableEngine(gomock.Any(), mockBackend).Return(assert.AnError)
			},
			body:       strings.NewReader("{\"engine_path\": \"/test\"}"),
			wantStatus: http.StatusInternalServerError,
		},
		{
			name: "success",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				mockBackend := secman.NewMockLogicalBackend(gomock.NewController(t))
				core.Router.(*secman.MockILogicalRouter).EXPECT().Resolve("/test").Return(mockBackend, nil)
				core.Auth.(*secman.MockIAuth).EXPECT().EnableEngine(gomock.Any(), mockBackend).Return(nil)
			},
			body:       strings.NewReader("{\"engine_path\": \"/test\"}"),
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
				"/api/sys/auth/enable",
				tt.body,
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
