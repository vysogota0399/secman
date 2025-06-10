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

func TestUnseal_Handler(t *testing.T) {
	tests := []struct {
		name       string
		body       io.Reader
		prepare    func(core *secman.Core)
		wantStatus int
	}{
		{
			name: "core is not sealed",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(false)
			},
			wantStatus: http.StatusNotModified,
		},
		{
			name: "error invalid body",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(true)
			},
			body:       strings.NewReader("invalid"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "error invalid key",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(true)
			},
			body:       strings.NewReader("{\"key\": \"invalid\"}"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "error unseal failed",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(true)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Unseal(gomock.Any(), gomock.Any()).Return(true, assert.AnError)
			},
			body:       strings.NewReader("{\"key\": \"3bPuOMYNtgI9osmR60PrKBvz27fhNYc6E+pZJVFRhgs=\"}"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "success",
			prepare: func(core *secman.Core) {
				core.IsSealed.Store(true)
				core.Barrier.(*secman.MockIBarrier).EXPECT().Unseal(gomock.Any(), gomock.Any()).Return(true, nil)
				core.Router.(*secman.MockILogicalRouter).EXPECT().PostUnsealEngines(gomock.Any()).Return(nil)
				core.Auth.(*secman.MockIAuth).EXPECT().PostUnseal(gomock.Any(), core.Router).Return(nil)
			},
			body:       strings.NewReader("{\"key\": \"3bPuOMYNtgI9osmR60PrKBvz27fhNYc6E+pZJVFRhgs=\"}"),
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
				"/api/sys/unseal",
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
