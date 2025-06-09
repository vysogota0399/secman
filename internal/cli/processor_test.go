package cli

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
)

func TestRun(t *testing.T) {
	ctrl := NewController(t)
	mockSession := NewMockISession(ctrl)
	mockClient := NewMockIClient(ctrl)
	mockLogger := NewLogger(t)
	MockCommands := map[string]ICommand{
		"mock": NewMockICommand(ctrl),
	}

	type args struct {
		args   []string
		cmds   map[string]ICommand
		s      ISession
		lg     *logging.ZapLogger
		c      *Config
		client IClient
	}
	tests := []struct {
		name    string
		args    args
		setup   func()
		wantErr bool
	}{
		{
			name: "should display usage when no args provided",
			args: args{
				args:   []string{},
				cmds:   MockCommands,
				s:      mockSession,
				lg:     mockLogger,
				c:      &Config{ServerURL: "http://localhost:8080"},
				client: mockClient,
			},
			setup: func() {
				cmd := MockCommands["mock"]
				cmdMock := cmd.(*MockICommand)
				cmdMock.EXPECT().
					Info().
					Return("mock")
			},
			wantErr: false,
		},
		{
			name: "should handle unknown command",
			args: args{
				args:   []string{"unknown"},
				cmds:   MockCommands,
				s:      mockSession,
				lg:     mockLogger,
				c:      &Config{ServerURL: "http://localhost:8080"},
				client: mockClient,
			},
			setup: func() {
				// No setup needed as we expect error output
			},
			wantErr: false,
		},
		{
			name: "should handle session init error",
			args: args{
				args:   []string{"mock"},
				cmds:   MockCommands,
				s:      mockSession,
				lg:     mockLogger,
				c:      &Config{ServerURL: "http://localhost:8080"},
				client: mockClient,
			},
			setup: func() {
				mockSession.EXPECT().
					Init(gomock.Any()).
					Return(assert.AnError)
			},
			wantErr: false,
		},
		{
			name: "should handle command parse error",
			args: args{
				args:   []string{"mock", "invalid"},
				cmds:   MockCommands,
				s:      mockSession,
				lg:     mockLogger,
				c:      &Config{ServerURL: "http://localhost:8080"},
				client: mockClient,
			},
			setup: func() {
				mockSession.EXPECT().
					Init(gomock.Any()).
					Return(nil)

				cmd := MockCommands["mock"]
				cmdMock := cmd.(*MockICommand)
				cmdMock.EXPECT().
					Parse(gomock.Any()).
					Return(assert.AnError)
			},
			wantErr: false,
		},
		{
			name: "should handle command successfully, persist session failed",
			args: args{
				args:   []string{"mock"},
				cmds:   MockCommands,
				s:      mockSession,
				lg:     mockLogger,
				c:      &Config{ServerURL: "http://localhost:8080"},
				client: mockClient,
			},
			setup: func() {
				mockSession.EXPECT().
					Init(gomock.Any()).
					Return(nil)

				cmd := MockCommands["mock"]
				cmdMock := cmd.(*MockICommand)
				cmdMock.EXPECT().
					Parse(gomock.Any()).
					Return(nil)

				cmdMock.EXPECT().
					Handle(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				mockSession.EXPECT().
					Persist().
					Return(assert.AnError)
			},
			wantErr: false,
		},
		{
			name: "should handle command successfully, persist session success",
			args: args{
				args:   []string{"mock"},
				cmds:   MockCommands,
				s:      mockSession,
				lg:     mockLogger,
				c:      &Config{ServerURL: "http://localhost:8080"},
				client: mockClient,
			},
			setup: func() {
				mockSession.EXPECT().
					Init(gomock.Any()).
					Return(nil)

				cmd := MockCommands["mock"]
				cmdMock := cmd.(*MockICommand)
				cmdMock.EXPECT().
					Parse(gomock.Any()).
					Return(nil)

				cmdMock.EXPECT().
					Handle(gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				mockSession.EXPECT().
					Persist().
					Return(nil)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			Run(tt.args.args, tt.args.cmds, tt.args.s, tt.args.lg, tt.args.c, tt.args.client)
		})
	}
}
