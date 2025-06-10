package tokens

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
	"golang.org/x/crypto/bcrypt"
)

func TestNewRootToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		tokensRepository *TokensRepository
	}
	tests := []struct {
		name string
		args args
		want *RootToken
	}{
		{
			name: "successful creation",
			args: args{
				tokensRepository: NewTokensRepository(secman.NewMockBarrierStorage(ctrl)),
			},
			want: &RootToken{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewRootToken(tt.args.tokensRepository)
			if got == nil {
				t.Errorf("NewRootToken() = nil, want non-nil")
			} else {
				assert.NotNil(t, got.tokensRepository)
			}
		})
	}
}

func TestRootToken_Gen(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogicalStorage := secman.NewMockILogicalStorage(ctrl)

	type fields struct {
		tokensRepository *TokensRepository
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
		prepare func(repo *TokensRepository)
	}{
		{
			name: "successful token generation",
			fields: fields{
				tokensRepository: &TokensRepository{storage: mockLogicalStorage},
			},
			args: args{
				ctx: context.Background(),
				key: "test-key",
			},
			wantErr: false,
			prepare: func(repo *TokensRepository) {
				mockLogicalStorage.EXPECT().
					Update(gomock.Any(), "test-key", gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "storage error",
			fields: fields{
				tokensRepository: &TokensRepository{storage: mockLogicalStorage},
			},
			args: args{
				ctx: context.Background(),
				key: "test-key",
			},
			wantErr: true,
			prepare: func(repo *TokensRepository) {
				mockLogicalStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &RootToken{
				tokensRepository: tt.fields.tokensRepository,
			}
			var err error
			tt.prepare(tt.fields.tokensRepository)
			got, err := rt.Gen(tt.args.ctx, tt.args.key)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, got)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRootToken_Compare(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogicalStorage := secman.NewMockILogicalStorage(ctrl)

	testToken := []byte("test-token")
	hashedToken, _ := bcrypt.GenerateFromPassword(testToken, 10)
	encodedToken := base64.StdEncoding.EncodeToString(testToken)

	// Create a token structure for storage
	storedToken := Token{
		Value: hashedToken,
		Key:   "test-path",
	}
	storedTokenJSON, _ := json.Marshal(storedToken)

	type fields struct {
		tokensRepository *TokensRepository
	}
	type args struct {
		ctx   context.Context
		path  string
		token string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(repo *TokensRepository)
	}{
		{
			name: "successful token comparison",
			fields: fields{
				tokensRepository: &TokensRepository{storage: mockLogicalStorage},
			},
			args: args{
				ctx:   context.Background(),
				path:  "test-path",
				token: encodedToken,
			},
			wantErr: false,
			prepare: func(repo *TokensRepository) {
				mockLogicalStorage.EXPECT().
					Get(gomock.Any(), "test-path").
					Return(secman.Entry{
						Value: string(storedTokenJSON),
						Key:   "test-path",
					}, nil)
			},
		},
		{
			name: "storage error",
			fields: fields{
				tokensRepository: &TokensRepository{storage: mockLogicalStorage},
			},
			args: args{
				ctx:   context.Background(),
				path:  "test-path",
				token: encodedToken,
			},
			wantErr: true,
			prepare: func(repo *TokensRepository) {
				mockLogicalStorage.EXPECT().
					Get(gomock.Any(), "test-path").
					Return(secman.Entry{}, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := &RootToken{
				tokensRepository: tt.fields.tokensRepository,
			}
			if tt.prepare != nil {
				tt.prepare(tt.fields.tokensRepository)
			}
			err := rt.Compare(tt.args.ctx, tt.args.path, tt.args.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
