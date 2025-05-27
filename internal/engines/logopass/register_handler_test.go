package logopass

import (
	"context"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/secman"
	iam_repositories "github.com/vysogota0399/secman/internal/secman/iam/repositories"
)

func TestBackend_registerHandler(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIam := NewMockIamAdapter(ctrl)

	type args struct {
		ctx    context.Context
		req    *secman.LogicalRequest
		params *secman.LogicalParams
	}
	tests := []struct {
		name    string
		args    args
		want    *secman.LogicalResponse
		wantErr bool
		setup   func()
	}{
		{
			name: "successful registration",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &RegisterPathBody{
						Login:    "testuser",
						Password: "testpass",
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  200,
				Message: map[string]interface{}{},
			},
			wantErr: false,
			setup: func() {
				mockIam.EXPECT().
					Register(gomock.Any(), iam_repositories.User{
						Login:    "testuser",
						Password: "testpass",
					}).
					Return(nil)
			},
		},
		{
			name: "user already exists",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &RegisterPathBody{
						Login:    "existinguser",
						Password: "testpass",
					},
				},
			},
			want: &secman.LogicalResponse{
				Status: 400,
				Message: map[string]interface{}{
					"error": "user with this login already exists",
				},
			},
			wantErr: false,
			setup: func() {
				mockIam.EXPECT().
					Register(gomock.Any(), iam_repositories.User{
						Login:    "existinguser",
						Password: "testpass",
					}).
					Return(ErrUserAlreadyExists)
			},
		},
		{
			name: "invalid body type",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: "invalid",
				},
			},
			want:    nil,
			wantErr: true,
			setup:   func() {},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			b := NewTestBackend(t)
			b.logopass.iam = mockIam
			got, err := b.registerHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.registerHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got.Status != tt.want.Status {
				t.Errorf("Backend.registerHandler() status = %v, want %v", got.Status, tt.want.Status)
			}
			if !tt.wantErr && got.Message != nil && tt.want.Message != nil {
				if gotMsg, ok := got.Message.(map[string]interface{}); ok {
					if wantMsg, ok := tt.want.Message.(map[string]interface{}); ok {
						if gotMsg["error"] != wantMsg["error"] {
							t.Errorf("Backend.registerHandler() message = %v, want %v", gotMsg, wantMsg)
						}
					}
				}
			}
		})
	}
}
