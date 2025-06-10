package http

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/config"
)

func TestStatus_Handler(t *testing.T) {
	tests := []struct {
		name       string
		prepare    func(core *secman.Core)
		wantStatus int
	}{
		{
			name: "core is sealed and not initialized",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(true)
				core.IsInitialized.Store(false)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Info().Return("sealed")
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "core is unsealed and initialized",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
				core.IsInitialized.Store(true)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Info().Return("unsealed")
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "core is sealed and initialized",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(true)
				core.IsInitialized.Store(true)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Info().Return("sealed")
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
				http.MethodGet,
				"/api/sys/status",
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
