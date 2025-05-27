package repositories

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewParamsRepository(t *testing.T) {
	ctrl := secman.NewController(t)
	mockStorage := secman.NewMockILogicalStorage(ctrl)
	logger := secman.NewLogger(t)

	type args struct {
		b  secman.BarrierStorage
		lg *logging.ZapLogger
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "creates new repository",
			args: args{
				b:  mockStorage,
				lg: logger,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewParamsRepository(tt.args.b, tt.args.lg)
			if got == nil {
				t.Error("NewParamsRepository() returned nil")
			}
			if got.storage.Prefix() != "auth/logopass" {
				t.Errorf("NewParamsRepository().storage.Prefix() = %v, want %v", got.storage.Prefix(), "auth/logopass")
			}
		})
	}
}

func TestParamsRepository_IsExist(t *testing.T) {
	ctrl := secman.NewController(t)
	mockStorage := secman.NewMockILogicalStorage(ctrl)
	logger := secman.NewLogger(t)

	type fields struct {
		lg      *logging.ZapLogger
		storage secman.ILogicalStorage
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
		setup   func()
	}{
		{
			name: "params exist",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want:    true,
			wantErr: false,
			setup: func() {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), "").
					Return(secman.Entry{
						Value: `{"token_ttl": 3600, "secret_key": "test-secret"}`,
					}, true, nil)
			},
		},
		{
			name: "params do not exist",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want:    false,
			wantErr: false,
			setup: func() {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), "").
					Return(secman.Entry{}, false, nil)
			},
		},
		{
			name: "storage error",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want:    false,
			wantErr: true,
			setup: func() {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), "").
					Return(secman.Entry{}, false, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ParamsRepository{
				lg:      tt.fields.lg,
				storage: tt.fields.storage,
			}

			if tt.setup != nil {
				tt.setup()
			}

			got, err := r.IsExist(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParamsRepository.IsExist() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParamsRepository.IsExist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamsRepository_Get(t *testing.T) {
	ctrl := secman.NewController(t)
	mockStorage := secman.NewMockILogicalStorage(ctrl)
	logger := secman.NewLogger(t)

	type fields struct {
		lg      *logging.ZapLogger
		storage secman.ILogicalStorage
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Params
		wantErr bool
		setup   func()
	}{
		{
			name: "successful get",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want: &Params{
				TokenTTL:  3600,
				SecretKey: "test-secret",
			},
			wantErr: false,
			setup: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "").
					Return(secman.Entry{
						Value: `{"token_ttl": 3600, "secret_key": "test-secret"}`,
					}, nil)
			},
		},
		{
			name: "params not found",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want:    nil,
			wantErr: true,
			setup: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "").
					Return(secman.Entry{}, secman.ErrEntryNotFound)
			},
		},
		{
			name: "invalid json",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want:    nil,
			wantErr: true,
			setup: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "").
					Return(secman.Entry{
						Value: `invalid json`,
					}, nil)
			},
		},
		{
			name: "storage error",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
			},
			want:    nil,
			wantErr: true,
			setup: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "").
					Return(secman.Entry{}, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ParamsRepository{
				lg:      tt.fields.lg,
				storage: tt.fields.storage,
			}

			if tt.setup != nil {
				tt.setup()
			}

			got, err := r.Get(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParamsRepository.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParamsRepository.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParamsRepository_Update(t *testing.T) {
	ctrl := secman.NewController(t)
	mockStorage := secman.NewMockILogicalStorage(ctrl)
	logger := secman.NewLogger(t)

	type fields struct {
		lg      *logging.ZapLogger
		storage secman.ILogicalStorage
	}
	type args struct {
		ctx    context.Context
		params *Params
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		setup   func()
	}{
		{
			name: "successful update",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
				params: &Params{
					TokenTTL:  3600,
					SecretKey: "test-secret",
				},
			},
			wantErr: false,
			setup: func() {
				mockStorage.EXPECT().
					Update(gomock.Any(), "", secman.Entry{
						Value: `{"token_ttl":3600,"secret_key":"test-secret"}`,
						Key:   "",
					}, time.Duration(0)).
					Return(nil)
			},
		},
		{
			name: "storage error",
			fields: fields{
				lg:      logger,
				storage: mockStorage,
			},
			args: args{
				ctx: context.Background(),
				params: &Params{
					TokenTTL:  3600,
					SecretKey: "test-secret",
				},
			},
			wantErr: true,
			setup: func() {
				mockStorage.EXPECT().
					Update(gomock.Any(), "", gomock.Any(), time.Duration(0)).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ParamsRepository{
				lg:      tt.fields.lg,
				storage: tt.fields.storage,
			}

			if tt.setup != nil {
				tt.setup()
			}

			if err := r.Update(tt.args.ctx, tt.args.params); (err != nil) != tt.wantErr {
				t.Errorf("ParamsRepository.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
