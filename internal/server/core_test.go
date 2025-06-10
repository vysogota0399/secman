package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/server/config"
)

func TestNewCore(t *testing.T) {
	type args struct {
		config            *config.Config
		isCoreInitialized bool
	}
	tests := []struct {
		name string
		args args
		want *Core
	}{
		{
			name: "core is initialized",
			args: args{
				config:            &config.Config{},
				isCoreInitialized: true,
			},
		},
		{
			name: "core is not initialized",
			args: args{
				config:            &config.Config{},
				isCoreInitialized: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, app := NewTestCore(t, tt.args.config, tt.args.isCoreInitialized)
			app.Start(context.Background())

			assert.Equal(t, tt.args.isCoreInitialized, core.IsInitialized.Load())
			assert.True(t, core.IsSealed.Load())
		})
	}
}

func TestCore_Init(t *testing.T) {
	type fields struct {
		IsInitialized *atomic.Bool
		Config        *config.Config
	}
	type args struct {
		coreRepository ICoreRepository
	}
	tests := []struct {
		name    string
		fields  fields
		args    *args
		wantErr bool
		prepare func(mockCoreRepository *MockICoreRepository)
	}{
		{
			name: "successful initialization",
			fields: fields{
				IsInitialized: &atomic.Bool{},
				Config:        &config.Config{},
			},
			args: &args{
				coreRepository: nil, // Will be set in the test
			},
			wantErr: false,
			prepare: func(mockCoreRepository *MockICoreRepository) {
				mockCoreRepository.EXPECT().
					SetCoreInitialized(gomock.Any(), true).
					Return(nil)
			},
		},
		{
			name: "already initialized",
			fields: fields{
				IsInitialized: &atomic.Bool{},
				Config:        &config.Config{},
			},
			args: &args{
				coreRepository: nil, // Will be set in the test
			},
			wantErr: true,
			prepare: func(mockCoreRepository *MockICoreRepository) {
				// No expectations needed as the core is already initialized
			},
		},
		{
			name: "set initialized fails",
			fields: fields{
				IsInitialized: &atomic.Bool{},
				Config:        &config.Config{},
			},
			args: &args{
				coreRepository: nil, // Will be set in the test
			},
			wantErr: true,
			prepare: func(mockCoreRepository *MockICoreRepository) {
				mockCoreRepository.EXPECT().
					SetCoreInitialized(gomock.Any(), true).
					Return(errors.New("failed to set initialized"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, app := NewTestCore(t, tt.fields.Config, tt.name == "already initialized")
			app.Start(context.Background())

			coreRepository := NewMockICoreRepository(NewController(t))
			tt.args.coreRepository = coreRepository

			if tt.prepare != nil {
				tt.prepare(coreRepository)
			}

			if err := core.Init(tt.args.coreRepository); (err != nil) != tt.wantErr {
				t.Errorf("Core.Init() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				assert.True(t, core.IsInitialized.Load())
			}
		})
	}
}

func TestCore_Unseal(t *testing.T) {
	type fields struct {
		Config *config.Config
	}
	type args struct {
		ctx context.Context
		key []byte
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantErr    bool
		prepare    func(core *Core)
		wantSealed bool
	}{
		{
			name: "successful unseal",
			fields: fields{
				Config: &config.Config{},
			},
			args: args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			wantErr: false,
			prepare: func(core *Core) {
				core.Barrier.(*MockIBarrier).EXPECT().
					Unseal(gomock.Any(), []byte("test-key")).
					Return(true, nil)
				core.Router.(*MockILogicalRouter).EXPECT().
					PostUnsealEngines(gomock.Any()).
					Return(nil)
				core.Auth.(*MockIAuth).EXPECT().
					PostUnseal(gomock.Any(), core.Router).
					Return(nil)
			},
		},
		{
			name: "unseal fails",
			fields: fields{
				Config: &config.Config{},
			},
			args: args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			wantErr: true,
			prepare: func(core *Core) {
				core.Barrier.(*MockIBarrier).EXPECT().
					Unseal(gomock.Any(), []byte("test-key")).
					Return(false, errors.New("unseal failed"))
			},
		},
		{
			name: "not unsealed",
			fields: fields{
				Config: &config.Config{},
			},
			args: args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			wantErr: false,
			prepare: func(core *Core) {
				core.Barrier.(*MockIBarrier).EXPECT().
					Unseal(gomock.Any(), []byte("test-key")).
					Return(false, nil)
			},
			wantSealed: true,
		},
		{
			name: "post unseal engines fails",
			fields: fields{
				Config: &config.Config{},
			},
			args: args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			wantErr: true,
			prepare: func(core *Core) {
				core.Barrier.(*MockIBarrier).EXPECT().
					Unseal(gomock.Any(), []byte("test-key")).
					Return(true, nil)
				core.Router.(*MockILogicalRouter).EXPECT().
					PostUnsealEngines(gomock.Any()).
					Return(errors.New("post unseal engines failed"))
			},
		},
		{
			name: "post unseal auth fails",
			fields: fields{
				Config: &config.Config{},
			},
			args: args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			wantErr: true,
			prepare: func(core *Core) {
				core.Barrier.(*MockIBarrier).EXPECT().
					Unseal(gomock.Any(), []byte("test-key")).
					Return(true, nil)
				core.Router.(*MockILogicalRouter).EXPECT().
					PostUnsealEngines(gomock.Any()).
					Return(nil)
				core.Auth.(*MockIAuth).EXPECT().
					PostUnseal(gomock.Any(), core.Router).
					Return(errors.New("post unseal auth failed"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, app := NewTestCore(t, tt.fields.Config, true)
			app.Start(context.Background())

			if tt.prepare != nil {
				tt.prepare(core)
			}

			err := core.Unseal(tt.args.ctx, tt.args.key)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantSealed, core.IsSealed.Load())
			}
		})
	}
}
