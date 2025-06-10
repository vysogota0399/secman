package tokens

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/server"
)

func TestToken_init(t *testing.T) {
	type fields struct {
		Value []byte
		Key   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "successful initialization",
			fields: fields{
				Value: nil,
				Key:   "test-key",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Token{
				Value: tt.fields.Value,
				Key:   tt.fields.Key,
			}
			if err := tr.init(); (err != nil) != tt.wantErr {
				t.Errorf("Token.init() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(tr.Value) != 32 {
				t.Errorf("Token.init() generated value length = %v, want %v", len(tr.Value), 32)
			}
		})
	}
}

func TestNewLogicalStorage(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		storage server.BarrierStorage
	}
	tests := []struct {
		name string
		args args
		want server.ILogicalStorage
	}{
		{
			name: "successful creation",
			args: args{
				storage: server.NewMockBarrierStorage(ctrl),
			},
			want: &server.LogicalStorage{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewLogicalStorage(tt.args.storage)
			if got == nil {
				t.Errorf("NewLogicalStorage() = nil, want non-nil")
			}
			if got.Prefix() != "sys/tokens" {
				t.Errorf("NewLogicalStorage().Prefix() = %v, want %v", got.Prefix(), "sys/tokens")
			}
		})
	}
}

func TestNewTokensRepository(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		barrier server.BarrierStorage
	}
	tests := []struct {
		name string
		args args
		want *TokensRepository
	}{
		{
			name: "successful creation",
			args: args{
				barrier: server.NewMockBarrierStorage(ctrl),
			},
			want: &TokensRepository{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokensRepository(tt.args.barrier)
			if got == nil {
				t.Fatal("NewTokensRepository() = nil, want non-nil")
			}
			if got.storage == nil {
				t.Fatal("NewTokensRepository().storage = nil, want non-nil")
			}
		})
	}
}

func TestTokensRepository_Find(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type fields struct {
		storage server.ILogicalStorage
	}
	type args struct {
		ctx context.Context
		key string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Token
		wantErr bool
		prepare func(storage *server.MockILogicalStorage)
	}{
		{
			name: "successful find",
			fields: fields{
				storage: server.NewMockILogicalStorage(ctrl),
			},
			args: args{
				ctx: context.Background(),
				key: "test-key",
			},
			want: Token{
				Value: []byte("test-value"),
				Key:   "test-key",
			},
			wantErr: false,
			prepare: func(storage *server.MockILogicalStorage) {
				token := Token{
					Value: []byte("test-value"),
					Key:   "test-key",
				}
				tokenBytes, _ := json.Marshal(token)
				storage.EXPECT().
					Get(gomock.Any(), "test-key").
					Return(server.Entry{
						Value: string(tokenBytes),
						Key:   "test-key",
					}, nil)
			},
		},
		{
			name: "entry not found",
			fields: fields{
				storage: server.NewMockILogicalStorage(ctrl),
			},
			args: args{
				ctx: context.Background(),
				key: "test-key",
			},
			want:    Token{},
			wantErr: true,
			prepare: func(storage *server.MockILogicalStorage) {
				storage.EXPECT().
					Get(gomock.Any(), "test-key").
					Return(server.Entry{}, server.ErrEntryNotFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := server.NewMockILogicalStorage(ctrl)
			r := &TokensRepository{
				storage: mockStorage,
			}

			if tt.prepare != nil {
				tt.prepare(mockStorage)
			}

			got, err := r.Find(tt.args.ctx, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokensRepository.Find() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TokensRepository.Find() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokensRepository_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type fields struct {
		storage server.ILogicalStorage
	}
	type args struct {
		ctx   context.Context
		token Token
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(storage *server.MockILogicalStorage)
	}{
		{
			name: "successful create",
			fields: fields{
				storage: server.NewMockILogicalStorage(ctrl),
			},
			args: args{
				ctx: context.Background(),
				token: Token{
					Value: []byte("test-value"),
					Key:   "test-key",
				},
			},
			wantErr: false,
			prepare: func(storage *server.MockILogicalStorage) {
				token := Token{
					Value: []byte("test-value"),
					Key:   "test-key",
				}
				tokenBytes, _ := json.Marshal(token)
				storage.EXPECT().
					Update(gomock.Any(), "test-key", server.Entry{
						Value: string(tokenBytes),
						Key:   "test-key",
					}, gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "storage error",
			fields: fields{
				storage: server.NewMockILogicalStorage(ctrl),
			},
			args: args{
				ctx: context.Background(),
				token: Token{
					Value: []byte("test-value"),
					Key:   "test-key",
				},
			},
			wantErr: true,
			prepare: func(storage *server.MockILogicalStorage) {
				token := Token{
					Value: []byte("test-value"),
					Key:   "test-key",
				}
				tokenBytes, _ := json.Marshal(token)
				storage.EXPECT().
					Update(gomock.Any(), "test-key", server.Entry{
						Value: string(tokenBytes),
						Key:   "test-key",
					}, gomock.Any()).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := server.NewMockILogicalStorage(ctrl)
			r := &TokensRepository{
				storage: mockStorage,
			}

			if tt.prepare != nil {
				tt.prepare(mockStorage)
			}

			if err := r.Create(tt.args.ctx, tt.args.token); (err != nil) != tt.wantErr {
				t.Errorf("TokensRepository.Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
