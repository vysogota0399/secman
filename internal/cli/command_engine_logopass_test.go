package cli

import (
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewLogopassCommand(t *testing.T) {
	tests := []struct {
		name string
		want *LogopassCommand
	}{
		{
			name: "should create new logopass command",
			want: &LogopassCommand{
				FSet: flag.NewFlagSet("logopass", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewLogopassCommand()
			if got.FSet.Name() != tt.want.FSet.Name() {
				t.Errorf("NewLogopassCommand() FSet name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestLogopassCommand_Parse(t *testing.T) {
	type fields struct {
		FSet      *flag.FlagSet
		username  string
		password  string
		operation string
	}
	type args struct {
		args []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "should parse login operation with credentials",
			fields: fields{
				FSet: flag.NewFlagSet("logopass", flag.ExitOnError),
			},
			args: args{
				args: []string{"logopass", "login", "-u", "testuser", "-p", "testpass"},
			},
			wantErr: false,
		},
		{
			name: "should parse register operation with credentials",
			fields: fields{
				FSet: flag.NewFlagSet("logopass", flag.ExitOnError),
			},
			args: args{
				args: []string{"logopass", "register", "-u", "testuser", "-p", "testpass"},
			},
			wantErr: false,
		},
		{
			name: "should return error for invalid operation",
			fields: fields{
				FSet: flag.NewFlagSet("logopass", flag.ExitOnError),
			},
			args: args{
				args: []string{"logopass", "invalid"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &LogopassCommand{
				FSet:      tt.fields.FSet,
				username:  tt.fields.username,
				password:  tt.fields.password,
				operation: tt.fields.operation,
			}
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("LogopassCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogopassCommand_Handle_Login(t *testing.T) {
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
			name: "should handle login operation successfully",
			args: args{
				args: []string{"logopass", "login", "-u", "testuser", "-p", "testpass"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: false,
			setup: func(mockSession *MockISession) {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				mockClient.EXPECT().
					Post(gomock.Any(), "engine/auth/logopass/login", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"token":"test-token"}`)),
					}, nil)

				mockSession.EXPECT().
					Login("test-token", "logopass")
			},
		},
		{
			name: "should handle login operation with missing credentials",
			args: args{
				args: []string{"logopass", "login"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
			},
		},
		{
			name: "should handle login operation with authentication error",
			args: args{
				args: []string{"logopass", "login", "-u", "testuser", "-p", "testpass"},
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
					Return(errors.New("authentication failed"))
			},
		},
		{
			name: "should handle login operation with server error",
			args: args{
				args: []string{"logopass", "login", "-u", "testuser", "-p", "testpass"},
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

				mockClient.EXPECT().
					Post(gomock.Any(), "engine/auth/logopass/login", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 500,
						Body:   io.NopCloser(strings.NewReader(`{"error":"internal server error"}`)),
					}, assert.AnError)
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

			c := NewLogopassCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("LogopassCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("LogopassCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogopassCommand_Handle_Register(t *testing.T) {
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
			name: "should handle register operation successfully",
			args: args{
				args: []string{"logopass", "register", "-u", "testuser", "-p", "testpass"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: false,
			setup: func(mockSession *MockISession) {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				mockClient.EXPECT().
					Post(gomock.Any(), "engine/auth/logopass/register", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle register operation with missing credentials",
			args: args{
				args: []string{"logopass", "register"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
			},
		},
		{
			name: "should handle register operation with authentication error",
			args: args{
				args: []string{"logopass", "register", "-u", "testuser", "-p", "testpass"},
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
					Return(errors.New("authentication failed"))
			},
		},
		{
			name: "should handle register operation with server error",
			args: args{
				args: []string{"logopass", "register", "-u", "testuser", "-p", "testpass"},
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

				mockClient.EXPECT().
					Post(gomock.Any(), "engine/auth/logopass/register", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 500,
						Body:   io.NopCloser(strings.NewReader(`{"error":"internal server error"}`)),
					}, assert.AnError)
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

			c := NewLogopassCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("LogopassCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("LogopassCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
