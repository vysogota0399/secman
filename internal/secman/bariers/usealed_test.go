package bariers

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewUnsealedBarrier(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storage := secman.NewMockIStorage(ctrl)
	barrier := NewUnsealedBarrier(storage)

	if barrier.storage != storage {
		t.Errorf("NewUnsealedBarrier() storage = %v, want %v", barrier.storage, storage)
	}
}

func TestUnsealedBarrier_Delete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(storage *secman.MockIStorage)
	}{
		{
			name: "successful delete",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Delete(gomock.Any(), "test/path").
					Return(nil)
			},
		},
		{
			name: "storage returns error",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			wantErr: true,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Delete(gomock.Any(), "test/path").
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := secman.NewMockIStorage(ctrl)
			b := NewUnsealedBarrier(storage)

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			if err := b.Delete(tt.args.ctx, tt.args.path); (err != nil) != tt.wantErr {
				t.Errorf("UnsealedBarrier.Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnsealedBarrier_Update(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx   context.Context
		path  string
		entry secman.Entry
		ttl   time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		prepare func(storage *secman.MockIStorage)
	}{
		{
			name: "successful update",
			args: args{
				ctx:   context.Background(),
				path:  "test/path",
				entry: secman.Entry{Value: "test value"},
				ttl:   time.Hour,
			},
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Update(gomock.Any(), "test/path", secman.PhysicalEntry{Value: []byte("test value")}, time.Hour).
					Return(nil)
			},
		},
		{
			name: "storage returns error",
			args: args{
				ctx:   context.Background(),
				path:  "test/path",
				entry: secman.Entry{Value: "test value"},
				ttl:   time.Hour,
			},
			wantErr: true,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Update(gomock.Any(), "test/path", secman.PhysicalEntry{Value: []byte("test value")}, time.Hour).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := secman.NewMockIStorage(ctrl)
			b := NewUnsealedBarrier(storage)

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			if err := b.Update(tt.args.ctx, tt.args.path, tt.args.entry, tt.args.ttl); (err != nil) != tt.wantErr {
				t.Errorf("UnsealedBarrier.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnsealedBarrier_Get(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    secman.Entry
		wantErr bool
		prepare func(storage *secman.MockIStorage)
	}{
		{
			name: "successful get",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want: secman.Entry{
				Path:  "test/path",
				Value: "test value",
			},
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{
						Path:  "test/path",
						Value: []byte("test value"),
					}, nil)
			},
		},
		{
			name: "entry not found",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			wantErr: true,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{}, secman.ErrEntryNotFound)
			},
		},
		{
			name: "storage returns error",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			wantErr: true,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{}, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := secman.NewMockIStorage(ctrl)
			b := NewUnsealedBarrier(storage)

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			got, err := b.Get(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnsealedBarrier.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnsealedBarrier.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnsealedBarrier_GetOk(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    secman.Entry
		want1   bool
		wantErr bool
		prepare func(storage *secman.MockIStorage)
	}{
		{
			name: "successful get",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want: secman.Entry{
				Path:  "test/path",
				Value: "test value",
			},
			want1:   true,
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{
						Path:  "test/path",
						Value: []byte("test value"),
					}, nil)
			},
		},
		{
			name: "entry not found",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			want1:   false,
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{}, secman.ErrEntryNotFound)
			},
		},
		{
			name: "storage returns error",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			want1:   false,
			wantErr: true,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{}, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := secman.NewMockIStorage(ctrl)
			b := NewUnsealedBarrier(storage)

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			got, got1, err := b.GetOk(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnsealedBarrier.GetOk() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnsealedBarrier.GetOk() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("UnsealedBarrier.GetOk() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestUnsealedBarrier_List(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    []secman.Entry
		wantErr bool
		prepare func(storage *secman.MockIStorage)
	}{
		{
			name: "successful list",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want: []secman.Entry{
				{
					Path:  "test/path/1",
					Value: "test value 1",
				},
				{
					Path:  "test/path/2",
					Value: "test value 2",
				},
			},
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					List(gomock.Any(), "test/path").
					Return([]secman.PhysicalEntry{
						{
							Path:  "test/path/1",
							Value: []byte("test value 1"),
						},
						{
							Path:  "test/path/2",
							Value: []byte("test value 2"),
						},
					}, nil)
			},
		},
		{
			name: "empty list",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    []secman.Entry{},
			wantErr: false,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					List(gomock.Any(), "test/path").
					Return([]secman.PhysicalEntry{}, nil)
			},
		},
		{
			name: "storage returns error",
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    nil,
			wantErr: true,
			prepare: func(storage *secman.MockIStorage) {
				storage.EXPECT().
					List(gomock.Any(), "test/path").
					Return(nil, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := secman.NewMockIStorage(ctrl)
			b := NewUnsealedBarrier(storage)

			if tt.prepare != nil {
				tt.prepare(storage)
			}

			got, err := b.List(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnsealedBarrier.List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnsealedBarrier.List() = %v, want %v", got, tt.want)
			}
		})
	}
}
