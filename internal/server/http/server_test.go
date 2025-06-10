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

func TestNewServer(t *testing.T) {
	ctx := context.Background()

	core, app := server.NewTestCore(t, &config.Config{
		Server: config.Server{
			Address: "localhost:8080",
		},
	}, true)

	if err := app.Start(ctx); err != nil {
		t.Fatalf("Failed to start app: %v", err)
	}

	router := NewTestRouter(t, core, nil)

	_, srvApp := NewTestServer(ctx, t, core, router)

	if err := srvApp.Start(ctx); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
}

func TestRouter(t *testing.T) {
	core, app := server.NewTestCore(t, &config.Config{
		Server: config.Server{
			Address: "localhost:8080",
		},
	}, false)

	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start app: %v", err)
	}

	router := NewTestRouter(t, core, nil)
	s, app := NewTestServer(context.Background(), t, core, router)
	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	srv, ok := s.srv.(*TestHTTPServer)
	if !ok {
		t.Fatalf("Failed to cast server to TestHTTPServer")
	}

	t.Run("route without mw", func(t *testing.T) {
		core.Barrier.(*server.MockIBarrier).EXPECT().Info().Return("sealed status")
		client := srv.Client()
		resp, err := client.Get(srv.URL + "/api/sys/status")
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("abort if not initialized", func(t *testing.T) {
		client := srv.Client()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/sys/unseal", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	coreRepository := server.NewMockICoreRepository(server.NewController(t))
	coreRepository.EXPECT().SetCoreInitialized(gomock.Any(), true).Return(nil)
	core.Init(coreRepository)

	t.Run("abort if not authorized by token", func(t *testing.T) {
		core.RootTokens.(*server.MockIRootTokens).EXPECT().Compare(gomock.Any(), gomock.Any(), gomock.Any()).Return(assert.AnError)
		client := srv.Client()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/sys/unseal", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		req.Header.Set("X-Secman-Token", "test")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("abort if not authorized by engine", func(t *testing.T) {
		core.Auth.(*server.MockIAuth).EXPECT().Authorize(gomock.Any()).Return(assert.AnError)
		client := srv.Client()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/sys/unseal", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("abort if sealed", func(t *testing.T) {
		client := srv.Client()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/sys/auth/enable", nil)
		if err != nil {
			t.Fatalf("Failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to get status: %v", err)
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}
