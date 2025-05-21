package secman

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestBackendRouter(t *testing.T) {
	type TestBody struct {
		Fiz string `json:"fiz"`
	}

	be := NewMockLogicalBackend(NewController(t))

	be.EXPECT().Paths().Return(map[string]map[string]*Path{
		"GET": {
			"/test": {
				Handler: func(ctx *gin.Context, params *LogicalParams) (*LogicalResponse, error) {
					return &LogicalResponse{
						Status:  http.StatusOK,
						Message: "test",
					}, nil
				},
			},
		},
		"POST": {
			"/test": {
				Handler: func(ctx *gin.Context, params *LogicalParams) (*LogicalResponse, error) {
					return &LogicalResponse{
						Status:  http.StatusOK,
						Message: "test",
					}, nil
				},
			},
		},
		"PUT": {
			"/test/:id": {
				Handler: func(ctx *gin.Context, params *LogicalParams) (*LogicalResponse, error) {
					return &LogicalResponse{
						Status:  http.StatusOK,
						Message: "test",
					}, nil
				},
				Fields: []Field{
					{
						Name:        "id",
						Description: "The ID of the test",
					},
				},
				Body: func() any { return &TestBody{} },
			},
		},
	})

	router, err := NewBackendRouter(be)
	assert.NoError(t, err)

	tk := []struct {
		Name       string
		request    *gin.Context
		wantErr    bool
		wantStatus int
	}{
		{
			Name: "GET '/api/v1/test'",
			request: &gin.Context{
				Request: &http.Request{
					Method: http.MethodGet,
					URL:    &url.URL{Path: "/api/v1/test"},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			Name: "POST '/api/v1/test'",
			request: &gin.Context{
				Request: &http.Request{
					Method: http.MethodPost,
					URL:    &url.URL{Path: "/api/v1/test"},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			Name: "PUT '/api/v1/test/123'",
			request: &gin.Context{
				Request: &http.Request{
					Body:   io.NopCloser(strings.NewReader(`{"fiz": "baz"}`)),
					Method: http.MethodPut,
					URL:    &url.URL{Path: "/api/v1/test/123"},
				},
			},
			wantStatus: http.StatusOK,
		},
		{
			Name: "PUT '/api/v1/test/123/params'",
			request: &gin.Context{
				Request: &http.Request{
					Method: http.MethodPut,
					URL:    &url.URL{Path: "/api/v1/test/123/params"},
				},
			},
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tk := range tk {
		t.Run(tk.Name, func(t *testing.T) {
			resp, err := router.Handle(tk.request)
			if tk.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				assert.Equal(t, tk.wantStatus, resp.Status)
			}
		})
	}
}
