package cli

import (
	"context"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewAuthCommand(t *testing.T) {
	tests := []struct {
		name string
		want *AuthCommand
	}{
		{
			name: "should create new auth command",
			want: &AuthCommand{
				FSet: flag.NewFlagSet("auth", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewAuthCommand()
			if got.FSet.Name() != tt.want.FSet.Name() {
				t.Errorf("NewAuthCommand() FSet name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestAuthCommand_Parse(t *testing.T) {
	type args struct {
		args []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "should parse enable flag",
			args: args{
				args: []string{"auth", "-enable"},
			},
			wantErr: false,
		},
		{
			name: "should parse enable flag with engine path",
			args: args{
				args: []string{"auth", "-enable", "/auth/logopass"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewAuthCommand()
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("AuthCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthCommand_Handle(t *testing.T) {
	ctrl := NewController(t)
	mockClient := NewMockIClient(ctrl)

	type args struct {
		args []string
		ctx  context.Context
		b    *strings.Builder
		o    *Operation
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		setup   func(mockSession *MockISession)
	}{
		{
			name: "should handle enable operation successfully",
			args: args{
				args: []string{"auth", "-enable", "/auth/logopass"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: false,
			setup: func(mockSession *MockISession) {
				// First authentication in Handle
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				// Second authentication in enableAuth
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				mockClient.EXPECT().
					Post(gomock.Any(), "sys/auth/enable", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle enable operation with missing engine path",
			args: args{
				args: []string{"auth", "-enable"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "should handle enable operation with auth engine not found",
			args: args{
				args: []string{"auth", "-enable", "/auth/nonexistent"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
				// First authentication in Handle
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				// Second authentication in enableAuth
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				mockClient.EXPECT().
					Post(gomock.Any(), "sys/auth/enable", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 404,
						Body:   io.NopCloser(strings.NewReader(`{"error":"auth engine not found"}`)),
					}, assert.AnError)
			},
		},
		{
			name: "should handle enable operation with authentication error",
			args: args{
				args: []string{"auth", "-enable", "/auth/logopass"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(assert.AnError)
			},
		},
		{
			name: "should handle unknown command",
			args: args{
				args: []string{"auth"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSession := NewMockISession(ctrl)
			tt.args.o.Session = mockSession

			if tt.setup != nil {
				tt.setup(mockSession)
			}

			c := NewAuthCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("AuthCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("AuthCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
