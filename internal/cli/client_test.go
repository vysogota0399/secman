package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
)

func TestNewClient(t *testing.T) {
	type args struct {
		s  ISession
		c  *Config
		lg *logging.ZapLogger
	}
	tests := []struct {
		name    string
		args    args
		want    *Client
		wantErr bool
	}{
		{
			name: "successful client creation",
			args: args{
				s:  NewMockISession(NewController(t)),
				c:  &Config{ServerURL: "http://localhost:8080"},
				lg: &logging.ZapLogger{},
			},
			want: &Client{
				session: NewMockISession(NewController(t)),
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      &logging.ZapLogger{},
			},
			wantErr: false,
		},
		{
			name: "error when server URL is empty",
			args: args{
				s:  NewMockISession(NewController(t)),
				c:  &Config{ServerURL: ""},
				lg: &logging.ZapLogger{},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewClient(tt.args.s, tt.args.c, tt.args.lg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Only compare non-nil fields when we expect success
				if got.session != tt.args.s {
					t.Errorf("NewClient().session = %v, want %v", got.session, tt.args.s)
				}
				if got.config != tt.args.c {
					t.Errorf("NewClient().config = %v, want %v", got.config, tt.args.c)
				}
				if got.lg != tt.args.lg {
					t.Errorf("NewClient().lg = %v, want %v", got.lg, tt.args.lg)
				}
				if got.client == nil {
					t.Error("NewClient().client is nil")
				}
			}
		})
	}
}

func TestClient_Post(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockHTTP := NewMockHTTP(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		session ISession
		client  HTTP
		config  *Config
		lg      *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		route   string
		body    io.Reader
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful post request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				body:    strings.NewReader(`{"key": "value"}`),
				headers: map[string]string{"Content-Type": "application/json"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "success"}`),
			},
			wantErr: false,
			setup: func() {
				expectedReq, _ := http.NewRequest(http.MethodPost, "http://localhost:8080/api/test", strings.NewReader(`{"key": "value"}`))
				expectedReq.Header.Set("Content-Type", "application/json")

				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"message": "success"}`)),
							Request: req,
						}
						return resp, nil
					})

				mockSession.EXPECT().
					Set(gomock.Any(), gomock.Any()).
					DoAndReturn(func(key, value string) {
						// Verify the cache key and value if needed
					})
			},
		},
		{
			name: "error on request failure",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				body:    strings.NewReader(`{"key": "value"}`),
				headers: map[string]string{"Content-Type": "application/json"},
			},
			want:    &Response{},
			wantErr: true,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					Return(nil, errors.New("connection error"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &Client{
				session: tt.fields.session,
				client:  tt.fields.client,
				config:  tt.fields.config,
				lg:      tt.fields.lg,
			}
			got, err := c.Post(tt.args.ctx, tt.args.route, tt.args.body, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Post() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Client.Post() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("Client.Post() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("Client.Post() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClient_Get(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockHTTP := NewMockHTTP(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		session ISession
		client  HTTP
		config  *Config
		lg      *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		route   string
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful get request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"data": "test"}`),
			},
			wantErr: false,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"data": "test"}`)),
							Request: req,
						}
						return resp, nil
					})

				mockSession.EXPECT().
					Set(gomock.Any(), gomock.Any()).
					DoAndReturn(func(key, value string) {
						// Verify the cache key and value if needed
					})
			},
		},
		{
			name: "unauthorized request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{},
			},
			want: &Response{
				Status: http.StatusUnauthorized,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
			wantErr: true,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusUnauthorized,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"error": "unauthorized"}`)),
							Request: req,
						}
						return resp, nil
					})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &Client{
				session: tt.fields.session,
				client:  tt.fields.client,
				config:  tt.fields.config,
				lg:      tt.fields.lg,
			}
			got, err := c.Get(tt.args.ctx, tt.args.route, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Client.Get() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("Client.Get() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("Client.Get() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClient_Put(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockHTTP := NewMockHTTP(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		session ISession
		client  HTTP
		config  *Config
		lg      *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		route   string
		body    io.Reader
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful put request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				body:    strings.NewReader(`{"key": "updated"}`),
				headers: map[string]string{"Content-Type": "application/json"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "updated"}`),
			},
			wantErr: false,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"message": "updated"}`)),
							Request: req,
						}
						return resp, nil
					})

				mockSession.EXPECT().
					Set(gomock.Any(), gomock.Any()).
					DoAndReturn(func(key, value string) {
						// Verify the cache key and value if needed
					})
			},
		},
		{
			name: "conflict on put request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				body:    strings.NewReader(`{"key": "conflict"}`),
				headers: map[string]string{"Content-Type": "application/json"},
			},
			want: &Response{
				Status: http.StatusConflict,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
			wantErr: true,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusConflict,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"error": "conflict"}`)),
							Request: req,
						}
						return resp, nil
					})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &Client{
				session: tt.fields.session,
				client:  tt.fields.client,
				config:  tt.fields.config,
				lg:      tt.fields.lg,
			}
			got, err := c.Put(tt.args.ctx, tt.args.route, tt.args.body, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Put() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Client.Put() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("Client.Put() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("Client.Put() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClient_Delete(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockHTTP := NewMockHTTP(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		session ISession
		client  HTTP
		config  *Config
		lg      *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		route   string
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful delete request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "deleted"}`),
			},
			wantErr: false,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"message": "deleted"}`)),
							Request: req,
						}
						return resp, nil
					})

				mockSession.EXPECT().
					Set(gomock.Any(), gomock.Any()).
					DoAndReturn(func(key, value string) {
						// Verify the cache key and value if needed
					})
			},
		},
		{
			name: "not found on delete request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/nonexistent",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusNotFound,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
			wantErr: true,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusNotFound,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"error": "not found"}`)),
							Request: req,
						}
						return resp, nil
					})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &Client{
				session: tt.fields.session,
				client:  tt.fields.client,
				config:  tt.fields.config,
				lg:      tt.fields.lg,
			}
			got, err := c.Delete(tt.args.ctx, tt.args.route, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.Delete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Client.Delete() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("Client.Delete() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("Client.Delete() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClient_MultipartRequest(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockHTTP := NewMockHTTP(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		session ISession
		client  HTTP
		config  *Config
		lg      *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		method  string
		route   string
		headers map[string]string
		fields  map[string]string
		files   []*Blob
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful multipart request with fields and files",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:    context.Background(),
				method: http.MethodPost,
				route:  "/upload",
				headers: map[string]string{
					"Authorization": "Bearer token",
				},
				fields: map[string]string{
					"description": "test file",
					"type":        "document",
				},
				files: []*Blob{
					{
						FieldName: "file",
						FileName:  "test.txt",
						Reader:    strings.NewReader("test content"),
					},
				},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "file uploaded successfully"}`),
			},
			wantErr: false,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						// Verify content type is multipart
						if !strings.Contains(req.Header.Get("Content-Type"), "multipart/form-data") {
							t.Error("expected multipart/form-data content type")
						}

						// Parse multipart form to verify fields and files
						err := req.ParseMultipartForm(10 << 20)
						if err != nil {
							t.Errorf("failed to parse multipart form: %v", err)
						}

						// Verify form fields
						if req.FormValue("description") != "test file" {
							t.Error("expected description field to be 'test file'")
						}
						if req.FormValue("type") != "document" {
							t.Error("expected type field to be 'document'")
						}

						// Verify file
						file, header, err := req.FormFile("file")
						if err != nil {
							t.Errorf("failed to get file: %v", err)
						}
						defer file.Close()

						if header.Filename != "test.txt" {
							t.Error("expected filename to be 'test.txt'")
						}

						content, err := io.ReadAll(file)
						if err != nil {
							t.Errorf("failed to read file content: %v", err)
						}
						if string(content) != "test content" {
							t.Error("expected file content to be 'test content'")
						}

						resp := &http.Response{
							StatusCode: http.StatusOK,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"message": "file uploaded successfully"}`)),
							Request: req,
						}
						return resp, nil
					})

				mockSession.EXPECT().
					Set(gomock.Any(), gomock.Any()).
					DoAndReturn(func(key, value string) {
						// Verify the cache key and value if needed
					})
			},
		},
		{
			name: "error on multipart request",
			fields: fields{
				session: mockSession,
				client:  mockHTTP,
				config:  &Config{ServerURL: "http://localhost:8080"},
				lg:      mockLogger,
			},
			args: args{
				ctx:    context.Background(),
				method: http.MethodPost,
				route:  "/upload",
				headers: map[string]string{
					"Authorization": "Bearer token",
				},
				fields: map[string]string{
					"description": "test file",
				},
				files: []*Blob{
					{
						FieldName: "file",
						FileName:  "test.txt",
						Reader:    strings.NewReader("test content"),
					},
				},
			},
			want: &Response{
				Status: http.StatusBadRequest,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
			wantErr: true,
			setup: func() {
				mockHTTP.EXPECT().
					Do(gomock.Any()).
					DoAndReturn(func(req *http.Request) (*http.Response, error) {
						resp := &http.Response{
							StatusCode: http.StatusBadRequest,
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body:    io.NopCloser(strings.NewReader(`{"error": "invalid file type"}`)),
							Request: req,
						}
						return resp, nil
					})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &Client{
				session: tt.fields.session,
				client:  tt.fields.client,
				config:  tt.fields.config,
				lg:      tt.fields.lg,
			}
			got, err := c.MultipartRequest(tt.args.ctx, tt.args.method, tt.args.route, tt.args.headers, tt.args.fields, tt.args.files...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.MultipartRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Client.MultipartRequest() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("Client.MultipartRequest() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("Client.MultipartRequest() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestNewClientCacheWrapper(t *testing.T) {
	ctrl := NewController(t)

	mockClient := NewMockIClient(ctrl)
	mockSession := NewMockISession(ctrl)
	mockLogger := NewLogger(t)

	type args struct {
		client  IClient
		session ISession
		lg      *logging.ZapLogger
	}
	tests := []struct {
		name string
		args args
		want *ClientCacheWrapper
	}{
		{
			name: "successful wrapper creation",
			args: args{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			want: &ClientCacheWrapper{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewClientCacheWrapper(tt.args.client, tt.args.session, tt.args.lg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewClientCacheWrapper() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClientCacheWrapper_Post(t *testing.T) {
	ctrl := NewController(t)

	mockClient := NewMockIClient(ctrl)
	mockSession := NewMockISession(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		client  IClient
		lg      *logging.ZapLogger
		session ISession
	}
	type args struct {
		ctx     context.Context
		route   string
		body    io.Reader
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful post request",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				body:    strings.NewReader(`{"key": "value"}`),
				headers: map[string]string{"Content-Type": "application/json"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "success"}`),
			},
			wantErr: false,
			setup: func() {
				mockClient.EXPECT().
					Post(gomock.Any(), "/test", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Body: strings.NewReader(`{"message": "success"}`),
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &ClientCacheWrapper{
				client:  tt.fields.client,
				lg:      tt.fields.lg,
				session: tt.fields.session,
			}
			got, err := c.Post(tt.args.ctx, tt.args.route, tt.args.body, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientCacheWrapper.Post() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("ClientCacheWrapper.Post() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("ClientCacheWrapper.Post() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("ClientCacheWrapper.Post() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClientCacheWrapper_Get(t *testing.T) {
	ctrl := NewController(t)

	mockClient := NewMockIClient(ctrl)
	mockSession := NewMockISession(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		client  IClient
		lg      *logging.ZapLogger
		session ISession
	}
	type args struct {
		ctx     context.Context
		route   string
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful get request",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"data": "test"}`),
			},
			wantErr: false,
			setup: func() {
				mockClient.EXPECT().
					Get(gomock.Any(), "/test", gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Body: strings.NewReader(`{"data": "test"}`),
					}, nil)

				mockSession.EXPECT().
					Set(gomock.Any(), gomock.Any()).
					DoAndReturn(func(key, value string) {
						// Verify the cache key and value if needed
					})
			},
		},
		{
			name: "get from cache on connection error",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"data": "cached"}`),
			},
			wantErr: false,
			setup: func() {
				// First attempt fails with connection error
				mockClient.EXPECT().
					Get(gomock.Any(), "/test", gomock.Any()).
					Return(nil, fmt.Errorf("dial tcp error: %w", &net.OpError{Op: "dial"}))

				// Then we try to get from cache
				cachedResponse := &ResponseCache{
					Status: http.StatusOK,
					Headers: map[string]string{
						"Content-Type": "application/json",
					},
					Body: []byte(`{"data": "cached"}`),
				}
				cachedJSON, _ := json.Marshal(cachedResponse)
				mockSession.EXPECT().
					Get("/test").
					Return(string(cachedJSON), true)
			},
		},
		{
			name: "get from cache on connection error, cache miss",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"data": "cached"}`),
			},
			wantErr: true,
			setup: func() {
				// First attempt fails with connection error
				mockClient.EXPECT().
					Get(gomock.Any(), "/test", gomock.Any()).
					Return(nil, fmt.Errorf("dial tcp error: %w", &net.OpError{Op: "dial"}))

				mockSession.EXPECT().
					Get("/test").
					Return("", false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &ClientCacheWrapper{
				client:  tt.fields.client,
				lg:      tt.fields.lg,
				session: tt.fields.session,
			}
			got, err := c.Get(tt.args.ctx, tt.args.route, tt.args.headers)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, got.Status, tt.want.Status)
				assert.Equal(t, got.Headers, tt.want.Headers)
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				assert.Equal(t, string(gotBody), string(wantBody))
			}
		})
	}
}

func TestClientCacheWrapper_Put(t *testing.T) {
	ctrl := NewController(t)

	mockClient := NewMockIClient(ctrl)
	mockSession := NewMockISession(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		client  IClient
		lg      *logging.ZapLogger
		session ISession
	}
	type args struct {
		ctx     context.Context
		route   string
		body    io.Reader
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful put request",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				body:    strings.NewReader(`{"key": "updated"}`),
				headers: map[string]string{"Content-Type": "application/json"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "updated"}`),
			},
			wantErr: false,
			setup: func() {
				mockClient.EXPECT().
					Put(gomock.Any(), "/test", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Body: strings.NewReader(`{"message": "updated"}`),
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &ClientCacheWrapper{
				client:  tt.fields.client,
				lg:      tt.fields.lg,
				session: tt.fields.session,
			}
			got, err := c.Put(tt.args.ctx, tt.args.route, tt.args.body, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientCacheWrapper.Put() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("ClientCacheWrapper.Put() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("ClientCacheWrapper.Put() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("ClientCacheWrapper.Put() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClientCacheWrapper_Delete(t *testing.T) {
	ctrl := NewController(t)

	mockClient := NewMockIClient(ctrl)
	mockSession := NewMockISession(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		client  IClient
		lg      *logging.ZapLogger
		session ISession
	}
	type args struct {
		ctx     context.Context
		route   string
		headers map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful delete request",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:     context.Background(),
				route:   "/test",
				headers: map[string]string{"Authorization": "Bearer token"},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "deleted"}`),
			},
			wantErr: false,
			setup: func() {
				mockClient.EXPECT().
					Delete(gomock.Any(), "/test", gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Body: strings.NewReader(`{"message": "deleted"}`),
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &ClientCacheWrapper{
				client:  tt.fields.client,
				lg:      tt.fields.lg,
				session: tt.fields.session,
			}
			got, err := c.Delete(tt.args.ctx, tt.args.route, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientCacheWrapper.Delete() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("ClientCacheWrapper.Delete() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("ClientCacheWrapper.Delete() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("ClientCacheWrapper.Delete() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}

func TestClientCacheWrapper_MultipartRequest(t *testing.T) {
	ctrl := NewController(t)

	mockClient := NewMockIClient(ctrl)
	mockSession := NewMockISession(ctrl)
	mockLogger := NewLogger(t)

	type fields struct {
		client  IClient
		lg      *logging.ZapLogger
		session ISession
	}
	type args struct {
		ctx     context.Context
		method  string
		route   string
		headers map[string]string
		fields  map[string]string
		files   []*Blob
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Response
		wantErr bool
		setup   func()
	}{
		{
			name: "successful multipart request",
			fields: fields{
				client:  mockClient,
				session: mockSession,
				lg:      mockLogger,
			},
			args: args{
				ctx:    context.Background(),
				method: http.MethodPost,
				route:  "/upload",
				headers: map[string]string{
					"Authorization": "Bearer token",
				},
				fields: map[string]string{
					"description": "test file",
					"type":        "document",
				},
				files: []*Blob{
					{
						FieldName: "file",
						FileName:  "test.txt",
						Reader:    strings.NewReader("test content"),
					},
				},
			},
			want: &Response{
				Status: http.StatusOK,
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
				Body: strings.NewReader(`{"message": "file uploaded successfully"}`),
			},
			wantErr: false,
			setup: func() {
				mockClient.EXPECT().
					MultipartRequest(gomock.Any(), http.MethodPost, "/upload", gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Body: strings.NewReader(`{"message": "file uploaded successfully"}`),
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &ClientCacheWrapper{
				client:  tt.fields.client,
				lg:      tt.fields.lg,
				session: tt.fields.session,
			}
			got, err := c.MultipartRequest(tt.args.ctx, tt.args.method, tt.args.route, tt.args.headers, tt.args.fields, tt.args.files...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ClientCacheWrapper.MultipartRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("ClientCacheWrapper.MultipartRequest() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Headers, tt.want.Headers) {
					t.Errorf("ClientCacheWrapper.MultipartRequest() headers = %v, want %v", got.Headers, tt.want.Headers)
				}
				// Compare body contents
				gotBody, _ := io.ReadAll(got.Body)
				wantBody, _ := io.ReadAll(tt.want.Body)
				if !reflect.DeepEqual(gotBody, wantBody) {
					t.Errorf("ClientCacheWrapper.MultipartRequest() body = %v, want %v", string(gotBody), string(wantBody))
				}
			}
		})
	}
}
