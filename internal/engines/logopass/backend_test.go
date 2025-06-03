package logopass

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	logopass_repositories "github.com/vysogota0399/secman/internal/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewBackend(t *testing.T) {
	type args struct {
		lg        *logging.ZapLogger
		logopass  *Logopass
		paramsRep ParamsRepository
	}
	tests := []struct {
		name string
		args args
		want *Backend
	}{
		{
			name: "creates new backend with default values",
			args: args{
				lg:        &logging.ZapLogger{},
				logopass:  &Logopass{},
				paramsRep: &logopass_repositories.ParamsRepository{},
			},
			want: &Backend{
				lg:        &logging.ZapLogger{},
				logopass:  &Logopass{},
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				paramsRep: &logopass_repositories.ParamsRepository{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBackend(tt.args.lg, tt.args.logopass, tt.args.paramsRep)

			// Only verify that the fields are initialized, not their internal values
			if got.lg == nil {
				t.Error("NewBackend().lg is nil")
			}
			if got.logopass == nil {
				t.Error("NewBackend().logopass is nil")
			}
			if got.paramsRep == nil {
				t.Error("NewBackend().paramsRep is nil")
			}
			if got.params == nil {
				t.Error("NewBackend().params is nil")
			}
			if got.exist == nil {
				t.Error("NewBackend().exist is nil")
			}
			if got.tokenReg == nil {
				t.Error("NewBackend().tokenReg is nil")
			} else if got.tokenReg.String() != `Bearer\s+(\S+)` {
				t.Errorf("NewBackend().tokenReg = %v, want %v", got.tokenReg.String(), `Bearer\s+(\S+)`)
			}
		})
	}
}

func TestBackend_Router(t *testing.T) {
	type fields struct {
		exist     *atomic.Bool
		params    *logopass_repositories.Params
		lg        *logging.ZapLogger
		paramsRep ParamsRepository
		logopass  *Logopass
		tokenReg  *regexp.Regexp
		router    *secman.BackendRouter
	}
	tests := []struct {
		name   string
		fields fields
		want   *secman.BackendRouter
	}{
		{
			name: "returns nil when router is not set",
			fields: fields{
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				lg:        &logging.ZapLogger{},
				paramsRep: &logopass_repositories.ParamsRepository{},
				logopass:  &Logopass{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				router:    nil,
			},
			want: nil,
		},
		{
			name: "returns set router",
			fields: fields{
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				lg:        &logging.ZapLogger{},
				paramsRep: &logopass_repositories.ParamsRepository{},
				logopass:  &Logopass{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				router:    &secman.BackendRouter{},
			},
			want: &secman.BackendRouter{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:     tt.fields.exist,
				params:    tt.fields.params,
				lg:        tt.fields.lg,
				paramsRep: tt.fields.paramsRep,
				logopass:  tt.fields.logopass,
				tokenReg:  tt.fields.tokenReg,
				router:    tt.fields.router,
			}
			if got := b.Router(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.Router() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_SetRouter(t *testing.T) {
	type fields struct {
		exist     *atomic.Bool
		params    *logopass_repositories.Params
		lg        *logging.ZapLogger
		paramsRep ParamsRepository
		logopass  *Logopass
		tokenReg  *regexp.Regexp
		router    *secman.BackendRouter
	}
	type args struct {
		router *secman.BackendRouter
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "sets router and can be retrieved",
			fields: fields{
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				lg:        &logging.ZapLogger{},
				paramsRep: &logopass_repositories.ParamsRepository{},
				logopass:  &Logopass{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				router:    nil,
			},
			args: args{
				router: &secman.BackendRouter{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:     tt.fields.exist,
				params:    tt.fields.params,
				lg:        tt.fields.lg,
				paramsRep: tt.fields.paramsRep,
				logopass:  tt.fields.logopass,
				tokenReg:  tt.fields.tokenReg,
				router:    tt.fields.router,
			}
			b.SetRouter(tt.args.router)
			if got := b.Router(); !reflect.DeepEqual(got, tt.args.router) {
				t.Errorf("Backend.Router() after SetRouter = %v, want %v", got, tt.args.router)
			}
		})
	}
}

func TestBackend_RootPath(t *testing.T) {
	type fields struct {
		exist     *atomic.Bool
		params    *logopass_repositories.Params
		lg        *logging.ZapLogger
		paramsRep ParamsRepository
		logopass  *Logopass
		tokenReg  *regexp.Regexp
		router    *secman.BackendRouter
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "returns correct root path",
			fields: fields{
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				lg:        &logging.ZapLogger{},
				paramsRep: &logopass_repositories.ParamsRepository{},
				logopass:  &Logopass{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				router:    nil,
			},
			want: "/auth/logopass",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:     tt.fields.exist,
				params:    tt.fields.params,
				lg:        tt.fields.lg,
				paramsRep: tt.fields.paramsRep,
				logopass:  tt.fields.logopass,
				tokenReg:  tt.fields.tokenReg,
				router:    tt.fields.router,
			}
			if got := b.RootPath(); got != tt.want {
				t.Errorf("Backend.RootPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_Help(t *testing.T) {
	type fields struct {
		exist     *atomic.Bool
		params    *logopass_repositories.Params
		lg        *logging.ZapLogger
		paramsRep ParamsRepository
		logopass  *Logopass
		tokenReg  *regexp.Regexp
		router    *secman.BackendRouter
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "returns correct help message",
			fields: fields{
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				lg:        &logging.ZapLogger{},
				paramsRep: &logopass_repositories.ParamsRepository{},
				logopass:  &Logopass{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				router:    nil,
			},
			want: "Logopass authentication backend, uses login and password to authenticate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:     tt.fields.exist,
				params:    tt.fields.params,
				lg:        tt.fields.lg,
				paramsRep: tt.fields.paramsRep,
				logopass:  tt.fields.logopass,
				tokenReg:  tt.fields.tokenReg,
				router:    tt.fields.router,
			}
			if got := b.Help(); got != tt.want {
				t.Errorf("Backend.Help() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_Paths(t *testing.T) {
	type fields struct {
		exist     *atomic.Bool
		params    *logopass_repositories.Params
		lg        *logging.ZapLogger
		paramsRep ParamsRepository
		logopass  *Logopass
		tokenReg  *regexp.Regexp
		router    *secman.BackendRouter
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]map[string]*secman.Path
	}{
		{
			name: "returns all available paths",
			fields: fields{
				exist:     &atomic.Bool{},
				params:    &logopass_repositories.Params{},
				lg:        &logging.ZapLogger{},
				paramsRep: &logopass_repositories.ParamsRepository{},
				logopass:  &Logopass{},
				tokenReg:  regexp.MustCompile(`Bearer\s+(\S+)`),
				router:    nil,
			},
			want: map[string]map[string]*secman.Path{
				"POST": {
					"/auth/logopass/login": {
						Description: "Login to the system by login and password",
						Body:        func() any { return &LoginPathBody{} },
						Handler:     nil, // Can't compare function pointers
						SkipAuth:    true,
					},
					"/auth/logopass/register": {
						Description: "Register a new user",
						Body:        func() any { return &RegisterPathBody{} },
						Handler:     nil, // Can't compare function pointers
						SkipAuth:    true,
					},
				},
				"GET": {
					"/auth/logopass/": {
						Description: "Get the params",
						Handler:     nil, // Can't compare function pointers
					},
				},
				"PUT": {
					"/auth/logopass/": {
						Description: "Set the params",
						Body:        func() any { return &ParamsPathBody{} },
						Handler:     nil,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:     tt.fields.exist,
				params:    tt.fields.params,
				lg:        tt.fields.lg,
				paramsRep: tt.fields.paramsRep,
				logopass:  tt.fields.logopass,
				tokenReg:  tt.fields.tokenReg,
				router:    tt.fields.router,
			}
			got := b.Paths()

			// Compare paths structure and metadata
			for method, paths := range tt.want {
				gotPaths, ok := got[method]
				if !ok {
					t.Errorf("Backend.Paths() missing method %s", method)
					continue
				}

				for path, wantPath := range paths {
					gotPath, ok := gotPaths[path]
					if !ok {
						t.Errorf("Backend.Paths() missing path %s for method %s", path, method)
						continue
					}

					if gotPath.Description != wantPath.Description {
						t.Errorf("Backend.Paths()[%s][%s].Description = %v, want %v",
							method, path, gotPath.Description, wantPath.Description)
					}

					if gotPath.SkipAuth != wantPath.SkipAuth {
						t.Errorf("Backend.Paths()[%s][%s].SkipAuth = %v, want %v",
							method, path, gotPath.SkipAuth, wantPath.SkipAuth)
					}

					// Verify that handlers and body functions are set
					if gotPath.Handler == nil && wantPath.Handler != nil {
						t.Errorf("Backend.Paths()[%s][%s].Handler is nil", method, path)
					}
					if gotPath.Body == nil && wantPath.Body != nil {
						t.Errorf("Backend.Paths()[%s][%s].Body is nil", method, path)
					}
				}
			}
		})
	}
}

func TestBackend_Enable(t *testing.T) {
	ctrl := secman.NewController(t)
	mockParamsRep := NewMockParamsRepository(ctrl)
	logger := secman.NewLogger(t)
	mockIam := NewMockIamAdapter(ctrl)
	logopass := NewLogopass(mockIam, logger)

	type args struct {
		ctx context.Context
		req *secman.LogicalRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *secman.LogicalResponse
		wantErr bool
		setup   func(*Backend)
	}{
		{
			name: "successful enable with provided params",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{"token_ttl": 3600, "secret_key": "test-secret"}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusOK,
				Message: "logopass enabled",
			},
			wantErr: false,
			setup: func(be *Backend) {
				mockParamsRep.EXPECT().
					Update(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "successful enable with auto-generated secret key",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{"token_ttl": 3600}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusOK,
				Message: "logopass enabled",
			},
			wantErr: false,
			setup: func(be *Backend) {
				mockParamsRep.EXPECT().
					Update(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "already enabled",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{"token_ttl": 3600, "secret_key": "test-secret"}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusNotModified,
				Message: gin.H{"message": "logopass: already enabled"},
			},
			wantErr: false,
			setup: func(be *Backend) {
				be.exist.Store(true)
			},
		},
		{
			name: "invalid json",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`invalid json`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "body is invalid or empty"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := NewBackend(logger, logopass, mockParamsRep)

			if tt.setup != nil {
				tt.setup(be)
			}

			got, err := be.Enable(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.Enable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.Enable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_PostUnseal(t *testing.T) {
	ctrl := secman.NewController(t)
	mockParamsRep := NewMockParamsRepository(ctrl)
	logger := secman.NewLogger(t)
	mockIam := NewMockIamAdapter(ctrl)
	logopass := NewLogopass(mockIam, logger)

	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		setup   func(*Backend)
	}{
		{
			name: "successful unseal",
			args: args{
				ctx: context.Background(),
			},
			wantErr: false,
			setup: func(be *Backend) {
				mockParamsRep.EXPECT().
					IsExist(gomock.Any()).
					Return(true, nil)
				mockParamsRep.EXPECT().
					Get(gomock.Any()).
					Return(&logopass_repositories.Params{
						TokenTTL:  time.Hour * 24,
						SecretKey: "test-secret",
					}, nil)
			},
		},
		{
			name: "params not found",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			setup: func(be *Backend) {
				mockParamsRep.EXPECT().
					IsExist(gomock.Any()).
					Return(false, nil)
			},
		},
		{
			name: "params repository error",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			setup: func(be *Backend) {
				mockParamsRep.EXPECT().
					IsExist(gomock.Any()).
					Return(false, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			be := NewBackend(logger, logopass, mockParamsRep)

			if tt.setup != nil {
				tt.setup(be)
			}

			if err := be.PostUnseal(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Backend.PostUnseal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
