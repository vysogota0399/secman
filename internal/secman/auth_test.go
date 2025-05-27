package secman

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap/zapcore"
)

type testConfig struct {
	level zapcore.Level
}

func (c *testConfig) LLevel() zapcore.Level {
	return c.level
}

func TestNewAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCoreRepo := NewMockICoreRepository(ctrl)
	logger, err := logging.MustZapLogger(&testConfig{level: zapcore.InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	type args struct {
		coreRepository ICoreRepository
		lg             *logging.ZapLogger
	}
	tests := []struct {
		name string
		args args
		want *Auth
	}{
		{
			name: "successful creation",
			args: args{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			want: &Auth{
				Engines:          []authPath{},
				engineCollection: []AuthorizeBackend{},
				coreRepository:   mockCoreRepo,
				authMtx:          sync.RWMutex{},
				lg:               logger,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAuth(tt.args.coreRepository, tt.args.lg)
			if !reflect.DeepEqual(got.Engines, tt.want.Engines) {
				t.Errorf("NewAuth().Engines = %v, want %v", got.Engines, tt.want.Engines)
			}
			if !reflect.DeepEqual(got.engineCollection, tt.want.engineCollection) {
				t.Errorf("NewAuth().engineCollection = %v, want %v", got.engineCollection, tt.want.engineCollection)
			}
			if got.coreRepository != tt.want.coreRepository {
				t.Errorf("NewAuth().coreRepository = %v, want %v", got.coreRepository, tt.want.coreRepository)
			}
			if got.lg != tt.want.lg {
				t.Errorf("NewAuth().lg = %v, want %v", got.lg, tt.want.lg)
			}
		})
	}
}

func TestAuth_PostUnseal(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCoreRepo := NewMockICoreRepository(ctrl)
	mockRouter := NewMockILogicalRouter(ctrl)
	mockEngine := NewMockLogicalBackend(ctrl)

	logger, err := logging.MustZapLogger(&testConfig{level: zapcore.InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	type fields struct {
		coreRepository ICoreRepository
		lg             *logging.ZapLogger
	}
	type args struct {
		ctx    context.Context
		router *MockILogicalRouter
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func(f *args)
		wantErr bool
	}{
		{
			name: "error getting core config",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: args{
				ctx:    context.Background(),
				router: mockRouter,
			},
			setup: func(f *args) {
				mockCoreRepo.EXPECT().
					GetCoreAuthConfig(gomock.Any()).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
		{
			name: "error router resolve",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: args{
				ctx:    context.Background(),
				router: mockRouter,
			},
			setup: func(f *args) {
				existingAuth := &Auth{
					Engines: []authPath{"test-engine"},
				}

				mockCoreRepo.EXPECT().
					GetCoreAuthConfig(gomock.Any()).
					Return(existingAuth, nil)

				mockRouter.EXPECT().
					Resolve(gomock.Any()).
					Return(nil, assert.AnError)
			},
			wantErr: true,
		},
		{
			name: "engine is not AuthorizeBackend",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: args{
				ctx:    context.Background(),
				router: mockRouter,
			},
			setup: func(f *args) {
				existingAuth := &Auth{
					Engines: []authPath{"test-engine"},
				}

				mockCoreRepo.EXPECT().
					GetCoreAuthConfig(gomock.Any()).
					Return(existingAuth, nil)

				mockRouter.EXPECT().
					Resolve(gomock.Any()).
					Return(mockEngine, nil)
			},
			wantErr: false,
		},
		{
			name: "successful post unseal",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: args{
				ctx:    context.Background(),
				router: mockRouter,
			},
			setup: func(f *args) {
				existingAuth := &Auth{
					Engines: []authPath{"test-engine"},
				}

				mockCoreRepo.EXPECT().
					GetCoreAuthConfig(gomock.Any()).
					Return(existingAuth, nil)

				authMockEngine := &mockAuthorizeBackend{
					MockLogicalBackend: mockEngine,
				}

				mockRouter.EXPECT().
					Resolve(gomock.Any()).
					Return(authMockEngine, nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(&tt.args)
			}
			a := NewAuth(tt.fields.coreRepository, tt.fields.lg)

			err := a.PostUnseal(tt.args.ctx, tt.args.router)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type mockAuthorizeBackend struct {
	*MockLogicalBackend
	authorizeFunc func(c *gin.Context) (bool, error)
}

func (m *mockAuthorizeBackend) Authorize(c *gin.Context) (bool, error) {
	return m.authorizeFunc(c)
}

func TestAuth_EnableEngine(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCoreRepo := NewMockICoreRepository(ctrl)
	logger, err := logging.MustZapLogger(&testConfig{level: zapcore.InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	type fields struct {
		coreRepository ICoreRepository
		lg             *logging.ZapLogger
	}
	type args struct {
		ctx    context.Context
		engine LogicalBackend
	}
	tests := []struct {
		name    string
		fields  fields
		args    *args
		setup   func(f *args)
		wantErr bool
	}{
		{
			name: "successful engine enable",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: &args{
				ctx: context.Background(),
				engine: &mockAuthorizeBackend{
					MockLogicalBackend: NewMockLogicalBackend(ctrl),
					authorizeFunc: func(c *gin.Context) (bool, error) {
						return true, nil
					},
				},
			},
			setup: func(f *args) {
				mockCoreRepo.EXPECT().
					UpdateCoreAuthConfig(gomock.Any(), gomock.Any()).
					Return(nil)
				f.engine.(*mockAuthorizeBackend).MockLogicalBackend.EXPECT().
					RootPath().
					Return("test-engine")
			},
			wantErr: false,
		},
		{
			name: "error updating core config",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: &args{
				ctx: context.Background(),
				engine: &mockAuthorizeBackend{
					MockLogicalBackend: NewMockLogicalBackend(ctrl),
					authorizeFunc: func(c *gin.Context) (bool, error) {
						return true, nil
					},
				},
			},
			setup: func(f *args) {
				mockCoreRepo.EXPECT().
					UpdateCoreAuthConfig(gomock.Any(), gomock.Any()).
					Return(assert.AnError)
				f.engine.(*mockAuthorizeBackend).MockLogicalBackend.EXPECT().
					RootPath().
					Return("test-engine")
			},
			wantErr: true,
		},
		{
			name: "engine is not AuthorizeBackend",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: &args{
				ctx:    context.Background(),
				engine: NewMockLogicalBackend(ctrl),
			},
			setup: func(f *args) {
				mockCoreRepo.EXPECT().
					UpdateCoreAuthConfig(gomock.Any(), gomock.Any()).
					Return(nil)

				f.engine.(*MockLogicalBackend).EXPECT().
					RootPath().
					Return("test-engine").AnyTimes()
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(tt.args)
			}

			a := NewAuth(tt.fields.coreRepository, tt.fields.lg)
			err := a.EnableEngine(tt.args.ctx, tt.args.engine)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuth_Authorize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockCoreRepo := NewMockICoreRepository(ctrl)
	logger, err := logging.MustZapLogger(&testConfig{level: zapcore.InfoLevel})
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	type fields struct {
		coreRepository ICoreRepository
		lg             *logging.ZapLogger
	}
	type args struct {
		c    *gin.Context
		auth *Auth
	}
	tests := []struct {
		name    string
		fields  fields
		args    *args
		setup   func(f *args)
		wantErr bool
	}{
		{
			name: "successful authorization",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: &args{
				c: &gin.Context{},
			},
			setup: func(f *args) {
				f.auth = NewAuth(mockCoreRepo, logger)
				f.auth.engineCollection = []AuthorizeBackend{
					&mockAuthorizeBackend{
						MockLogicalBackend: NewMockLogicalBackend(ctrl),
						authorizeFunc: func(c *gin.Context) (bool, error) {
							return true, nil
						},
					},
				}
			},
			wantErr: false,
		},
		{
			name: "unauthorized",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: &args{
				c: &gin.Context{},
			},
			setup: func(f *args) {
				f.auth = NewAuth(mockCoreRepo, logger)
				f.auth.engineCollection = []AuthorizeBackend{
					&mockAuthorizeBackend{
						MockLogicalBackend: NewMockLogicalBackend(ctrl),
						authorizeFunc: func(c *gin.Context) (bool, error) {
							return false, nil
						},
					},
				}
			},
			wantErr: true,
		},
		{
			name: "authorization error",
			fields: fields{
				coreRepository: mockCoreRepo,
				lg:             logger,
			},
			args: &args{
				c: &gin.Context{},
			},
			setup: func(f *args) {
				f.auth = NewAuth(mockCoreRepo, logger)
				f.auth.engineCollection = []AuthorizeBackend{
					&mockAuthorizeBackend{
						MockLogicalBackend: NewMockLogicalBackend(ctrl),
						authorizeFunc: func(c *gin.Context) (bool, error) {
							return false, assert.AnError
						},
					},
				}
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup(tt.args)
			}

			err := tt.args.auth.Authorize(tt.args.c)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
