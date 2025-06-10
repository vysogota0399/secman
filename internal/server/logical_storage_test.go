package server

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func TestLogicalStorage_Prefix(t *testing.T) {
	type fields struct {
		b      BarrierStorage
		prefix string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "returns correct prefix",
			fields: fields{
				b:      nil,
				prefix: "test/prefix",
			},
			want: "test/prefix",
		},
		{
			name: "returns empty prefix",
			fields: fields{
				b:      nil,
				prefix: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			if got := s.Prefix(); got != tt.want {
				t.Errorf("LogicalStorage.Prefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewLogicalStorage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBarrier := NewMockBarrierStorage(ctrl)

	type args struct {
		b    BarrierStorage
		path string
	}
	tests := []struct {
		name string
		args args
		want *LogicalStorage
	}{
		{
			name: "creates new logical storage with prefix",
			args: args{
				b:    mockBarrier,
				path: "test/path",
			},
			want: &LogicalStorage{
				b:      mockBarrier,
				prefix: "test/path",
			},
		},
		{
			name: "creates new logical storage with empty prefix",
			args: args{
				b:    mockBarrier,
				path: "",
			},
			want: &LogicalStorage{
				b:      mockBarrier,
				prefix: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewLogicalStorage(tt.args.b, tt.args.path); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLogicalStorage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogicalStorage_Get(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBarrier := NewMockBarrierStorage(ctrl)
	ctx := context.Background()

	type fields struct {
		b      BarrierStorage
		prefix string
	}
	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Entry
		wantErr bool
		setup   func()
	}{
		{
			name: "successfully gets entry",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx:  ctx,
				path: "test/path",
			},
			want: Entry{
				Key:   "/test/path",
				Value: "test-value",
				Path:  "test/prefix/test/path",
			},
			wantErr: false,
			setup: func() {
				mockBarrier.EXPECT().
					Get(ctx, "test/prefix/test/path").
					Return(Entry{Path: "test/prefix/test/path", Value: "test-value"}, nil)
			},
		},
		{
			name: "returns error when barrier storage fails",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx:  ctx,
				path: "test/path",
			},
			want:    Entry{},
			wantErr: true,
			setup: func() {
				mockBarrier.EXPECT().
					Get(ctx, "test/prefix/test/path").
					Return(Entry{}, errors.New("storage error"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			got, err := s.Get(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("LogicalStorage.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LogicalStorage.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogicalStorage_GetOk(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBarrier := NewMockBarrierStorage(ctrl)
	ctx := context.Background()

	type fields struct {
		b      BarrierStorage
		prefix string
	}
	type args struct {
		ctx context.Context
		key string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Entry
		want1   bool
		wantErr bool
		setup   func()
	}{
		{
			name: "successfully gets entry that exists",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			want: Entry{
				Key:   "test/prefix/test/path",
				Value: "test-value",
			},
			want1:   true,
			wantErr: false,
			setup: func() {
				mockBarrier.EXPECT().
					GetOk(ctx, "test/prefix/test/path").
					Return(Entry{Value: "test-value", Key: "test/prefix/test/path"}, true, nil)
			},
		},
		{
			name: "returns false when entry doesn't exist",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			want:    Entry{},
			want1:   false,
			wantErr: false,
			setup: func() {
				mockBarrier.EXPECT().
					GetOk(ctx, "test/prefix/test/path").
					Return(Entry{}, false, nil)
			},
		},
		{
			name: "returns error when barrier storage fails",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			want:    Entry{},
			want1:   false,
			wantErr: true,
			setup: func() {
				mockBarrier.EXPECT().
					GetOk(ctx, "test/prefix/test/path").
					Return(Entry{}, false, errors.New("storage error"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			got, got1, err := s.GetOk(tt.args.ctx, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("LogicalStorage.GetOk() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LogicalStorage.GetOk() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("LogicalStorage.GetOk() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestLogicalStorage_Update(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBarrier := NewMockBarrierStorage(ctrl)
	ctx := context.Background()

	type fields struct {
		b      BarrierStorage
		prefix string
	}
	type args struct {
		ctx   context.Context
		key   string
		value Entry
		ttl   time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		setup   func()
	}{
		{
			name: "successfully updates entry",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
				value: Entry{
					Key:   "test/path",
					Value: "test-value",
				},
				ttl: time.Hour,
			},
			wantErr: false,
			setup: func() {
				mockBarrier.EXPECT().
					Update(ctx, "test/prefix/test/path", Entry{Key: "test/path", Value: "test-value"}, time.Hour).
					Return(nil)
			},
		},
		{
			name: "returns error when barrier storage fails",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
				value: Entry{
					Key:   "test/path",
					Value: "test-value",
				},
				ttl: time.Hour,
			},
			wantErr: true,
			setup: func() {
				mockBarrier.EXPECT().
					Update(ctx, "test/prefix/test/path", Entry{Key: "test/path", Value: "test-value"}, time.Hour).
					Return(errors.New("storage error"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			if err := s.Update(tt.args.ctx, tt.args.key, tt.args.value, tt.args.ttl); (err != nil) != tt.wantErr {
				t.Errorf("LogicalStorage.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogicalStorage_Delete(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBarrier := NewMockBarrierStorage(ctrl)
	ctx := context.Background()

	type fields struct {
		b      BarrierStorage
		prefix string
	}
	type args struct {
		ctx context.Context
		key string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		setup   func()
	}{
		{
			name: "successfully deletes entry",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			wantErr: false,
			setup: func() {
				mockBarrier.EXPECT().
					Delete(ctx, "test/prefix/test/path").
					Return(nil)
			},
		},
		{
			name: "returns error when barrier storage fails",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			wantErr: true,
			setup: func() {
				mockBarrier.EXPECT().
					Delete(ctx, "test/prefix/test/path").
					Return(errors.New("storage error"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			if err := s.Delete(tt.args.ctx, tt.args.key); (err != nil) != tt.wantErr {
				t.Errorf("LogicalStorage.Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogicalStorage_List(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockBarrier := NewMockBarrierStorage(ctrl)
	ctx := context.Background()

	type fields struct {
		b      BarrierStorage
		prefix string
	}
	type args struct {
		ctx context.Context
		key string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []Entry
		wantErr bool
		setup   func()
	}{
		{
			name: "successfully lists entries",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			want: []Entry{
				{Path: "test/prefix/test/path", Value: "value1", Key: "/test/path"},
				{Path: "test/prefix/test/path", Value: "value2", Key: "/test/path"},
			},
			wantErr: false,
			setup: func() {
				mockBarrier.EXPECT().
					List(ctx, "test/prefix/test/path").
					Return([]Entry{
						{Path: "test/prefix/test/path", Value: "value1"},
						{Path: "test/prefix/test/path", Value: "value2"},
					}, nil)
			},
		},
		{
			name: "returns error when barrier storage fails",
			fields: fields{
				b:      mockBarrier,
				prefix: "test/prefix",
			},
			args: args{
				ctx: ctx,
				key: "test/path",
			},
			want:    nil,
			wantErr: true,
			setup: func() {
				mockBarrier.EXPECT().
					List(ctx, "test/prefix/test/path").
					Return(nil, errors.New("storage error"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			got, err := s.List(tt.args.ctx, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("LogicalStorage.List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LogicalStorage.List() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogicalStorage_relativePath(t *testing.T) {
	type fields struct {
		b      BarrierStorage
		prefix string
	}
	type args struct {
		p string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "joins prefix and path",
			fields: fields{
				b:      nil,
				prefix: "test/prefix",
			},
			args: args{
				p: "test/path",
			},
			want: "test/prefix/test/path",
		},
		{
			name: "returns path when prefix is empty",
			fields: fields{
				b:      nil,
				prefix: "",
			},
			args: args{
				p: "test/path",
			},
			want: "test/path",
		},
		{
			name: "returns prefix when path is empty",
			fields: fields{
				b:      nil,
				prefix: "test/prefix",
			},
			args: args{
				p: "",
			},
			want: "test/prefix",
		},
		{
			name: "returns empty string when both prefix and path are empty",
			fields: fields{
				b:      nil,
				prefix: "",
			},
			args: args{
				p: "",
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &LogicalStorage{
				b:      tt.fields.b,
				prefix: tt.fields.prefix,
			}
			if got := s.relativePath(tt.args.p); got != tt.want {
				t.Errorf("LogicalStorage.relativePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
