package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/server"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
)

func NewTestRouter(t *testing.T, core *server.Core, coreRepository server.ICoreRepository) *Router {
	t.Helper()
	return NewRouter(core, coreRepository)
}

type TestHTTPServer struct {
	*httptest.Server
}

func (s *TestHTTPServer) ListenAndServeTLS(certFile, keyFile string) error {
	return nil
}

func (s *TestHTTPServer) Shutdown(ctx context.Context) error {
	s.Server.Close()
	return nil
}

var _ HTTPServer = &TestHTTPServer{}

func NewTestServer(ctx context.Context, t *testing.T, core *server.Core, router *Router) (*Server, *fxtest.App) {
	t.Helper()

	var (
		l fx.Lifecycle
		s fx.Shutdowner
	)

	app := fxtest.New(
		t,
		fx.Populate(&l, &s),
	)

	t.Cleanup(func() {
		err := app.Stop(ctx)
		if err != nil {
			t.Fatalf("failed to stop app: %v", err)
		}
	})

	tmpDir, err := os.MkdirTemp("", "certs")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(tmpDir)
	})

	// Create a test config file
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	testCert := []byte(`
-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUKmVjUEm1gJeC9xCy/osF53V2T7EwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MDUyNzIwMDgyNFoXDTI2MDUy
NzIwMDgyNFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAq4PdtqaW/WSb1cej3aDEC4Rno7IM6fX3HAy/3fk7l2y0
9TrtnArcwSVYk3MeUJLnDH8p8pzh/HlGZ9feEg58IKoBzaNJOqwfmLxXm4TDvbq6
/4weqoIronmvA9KeuHqH6nNh15hI4pmsFDvPuGUtQADQmHPjsqTN39S8ASFtHPss
LcYiNWfZRoN49jWUx8UDQRXInBA/YHKuIod6QLwDLbsJqHCZLKU1npVpEV2peyK9
pbhCBZ2NK23Atsdawxi7F6rqAtjuQ58OWEhJqWMOlU1HCZW44nL/aTw5ZFYSXIXz
JvYItZUq5T8ukiP/eQdf99FU4kcvxQ6xwwA4GaYiQQIDAQABo28wbTAdBgNVHQ4E
FgQUjM6ivVbxYAVGbCkOxXcPevKmOtowHwYDVR0jBBgwFoAUjM6ivVbxYAVGbCkO
xXcPevKmOtowDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAF+nBsdelWbgnSWEUUoRcCS2EaqHgqGE
9usSkRoy3BBBhF2zI7Zmli+e2dyFX0754/CzoO9U//N9wgJiigO9vvELw5PXsEOK
N5O6YtUriLypYQMRUH94/rjF2aWaGpzPJqjOL6i4Tr28JjEF5eKO1XWSWTTUiQTX
Dj956M3vF9IABlODlNOwxT06bBEYEkS9RGrz4giFp20vKLQdZ3WT5sq96xrD66iR
yJe4CyifrYyGa57lQS5FmVRlUXg1DOF0WCtPsjhtdTxXwTTkZCcA27JT3EkZj3h7
qsCxb2X/H+h2AgVYmq/4MdkeRHrsclMuI4xkcbmWKkU4c2fJJtg8oIA=
-----END CERTIFICATE-----
	`)

	testKey := []byte(`
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCrg922ppb9ZJvV
x6PdoMQLhGejsgzp9fccDL/d+TuXbLT1Ou2cCtzBJViTcx5QkucMfynynOH8eUZn
194SDnwgqgHNo0k6rB+YvFebhMO9urr/jB6qgiuiea8D0p64eofqc2HXmEjimawU
O8+4ZS1AANCYc+OypM3f1LwBIW0c+ywtxiI1Z9lGg3j2NZTHxQNBFcicED9gcq4i
h3pAvAMtuwmocJkspTWelWkRXal7Ir2luEIFnY0rbcC2x1rDGLsXquoC2O5Dnw5Y
SEmpYw6VTUcJlbjicv9pPDlkVhJchfMm9gi1lSrlPy6SI/95B1/30VTiRy/FDrHD
ADgZpiJBAgMBAAECggEAIvZOKXejczNBRe58c4bcN6nNk5ONqNp7/RKHQPkXYepl
p9CTk3muXsvdVq9CeHO9l/FLDHrY4SWaibv5923O9Tyagf/dQ1HHXhPUeu3xFbmc
+U8niCPhP6001R9nvdyyXIMZKIDRKKnhJz26/dBYDUItQ0pqWaXZFp2vlj5pVtzy
CoiCRVukZNdQ6Re9ctRq3lOojGJpPJEW3IIBCy5G5uEke4794fC9+VW0KiMqurt3
J4eS2FApjLSxvYTh/9XW4MDm62Lz70/ZFhQe0ZivUvZBbZLtN9n7Q6TaS0cAe+SW
aEA5Cn/wvLN7171+3lAL9of8q7aUJib5d0JlLo59PQKBgQDRmEmR71zg52MJQDOS
u3bWsLuZCh5YJtGurcCiMM5tbT4ONb7VOlZXPSDaXUdXsjR0E9jvSE2HnjlMV4Uw
m9YB/itHJEkNL+L/JWpAeGm0pFGXfjTOqixtqC3npo38TXuYF7tIuZCPBHWYlmJZ
YQAYl9EmkYDsvRrQuNtsebOY1QKBgQDRfT1tEcOEXYqwYxLHh0opFMamPoQQlp1c
9X2gfdH/pGxrLWl1764uWaSgkPIoOQnsGBCS6bZpMNrcM44xSYz5gPtN9CWCm/ZE
p5Qy8VqG9OVG6NVT7QKXkU9IP5z3CA8d3wI7v2MtZbXfENzOHTkhVd/ITHyfPOC4
BaXfPluZvQKBgFaPaELm8hrINPSLGUGOPmQoFTH9Jc8OKSbVB2t0cKxso2ZG+Asj
zqi0zC6iu2YSaOtPjxYzbCGITO2kb5NFqLql98WnzKuvjTYGg70gfbdm7XN9Yd3A
Fh0ridnTxWvfrB2CH4zHZlZKZy6fXPrAvsNpX61oBjC/YKW20pgYIv4JAoGANIgF
ST51GtIiHw0Y/nPMgvS0w6dVkptSJqdgs0gZytM+ZLnkgjByKylLgQAX2UJEXLHE
JjL5DPO1ThaXh4B8G2zel7OrXE8juB+VqBihrMnoXJmyNPNv/PXxPZrGD6Qztjff
5X+erRmeO6uM0xq84sEX9rBHZ97qMvsnlw2aBrkCgYEAzDdS6wddB0S4TqZrT95H
xUFT8geyXmLhJXAOUGQUR0sEtbV7b3yC9BDVzHZjMREOqJ3yO1rGUVpj9uUXWyNR
MZgsIuzEEZcaQGWZ6DJQfNSCNyfs6jwDYc4k8Z53pxQjz74VzY+z7wo8nfLNc80e
CV/gKunh63wqKg5CuyKNDVI=
-----END PRIVATE KEY-----
	`)
	if err := os.WriteFile(certPath, testCert, 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	if err := os.WriteFile(keyPath, testKey, 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	core.Config.Server.CertPath = certPath
	core.Config.Server.KeyPath = keyPath

	server, err := NewServer(l, core, router, core.Log)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	server.srv = &TestHTTPServer{
		Server: httptest.NewTLSServer(router.router),
	}

	return server, app
}

func NewTestClient(ctx context.Context, t *testing.T, core *server.Core, router *Router, method string, path string, body io.Reader, authorizeByRootToken bool) (*http.Client, *http.Request) {
	t.Helper()

	s, app := NewTestServer(ctx, t, core, router)
	app.Start(ctx)

	testServer := s.srv.(*TestHTTPServer)
	client := testServer.Client()

	req, err := http.NewRequest(method, testServer.URL+path, body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	if authorizeByRootToken {
		req.Header.Set("X-Secman-Token", "token")
		core.RootTokens.(*server.MockIRootTokens).EXPECT().Compare(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
	}

	return client, req
}
