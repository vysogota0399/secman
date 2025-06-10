package logopass

import (
	"context"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/server"
	"github.com/vysogota0399/secman/internal/server/iam/repositories"
)

func TestBackend_LoginHandler(t *testing.T) {
	type args struct {
		ctx    context.Context
		req    *server.LogicalRequest
		params *server.LogicalParams
	}
	tests := []struct {
		name    string
		args    args
		want    *server.LogicalResponse
		wantErr bool
		setup   func(*MockIamAdapter)
	}{
		{
			name: "StatusUnauthorized login",
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &server.LogicalParams{
					Body: &LoginPathBody{
						Login:    "testuser",
						Password: "testpass",
					},
				},
			},
			want: &server.LogicalResponse{
				Status: http.StatusUnauthorized,
			},
			wantErr: false,
			setup: func(mock *MockIamAdapter) {
				mock.EXPECT().
					GetUser(gomock.Any(), gomock.Any()).
					Return(repositories.User{
						Login:    "testuser",
						Password: "testpass",
					}, nil)
			},
		},
		{
			name: "invalid class",
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &server.LogicalParams{
					Body: "invalid",
				},
			},
			want: &server.LogicalResponse{
				Status:  400,
				Message: gin.H{"error": "invalid credentials"},
			},
			wantErr: true,
			setup: func(mock *MockIamAdapter) {
				// No expectations needed for missing credentials case
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewTestBackend(t)
			if tt.setup != nil {
				tt.setup(b.logopass.iam.(*MockIamAdapter))
			}
			got, err := b.LoginHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.Status, got.Status)
			}
		})
	}
}
