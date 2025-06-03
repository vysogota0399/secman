package cli

import (
	"context"
	"flag"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewEngineCommand(t *testing.T) {
	tests := []struct {
		name string
		want *EngineCommand
	}{
		{
			name: "should create new engine command",
			want: &EngineCommand{
				FSet: flag.NewFlagSet("engine", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewEngineCommand(); !reflect.DeepEqual(got.FSet.Name(), tt.want.FSet.Name()) {
				t.Errorf("NewEngineCommand() FSet name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestEngineCommand_Parse(t *testing.T) {
	type fields struct {
		FSet *flag.FlagSet
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
			name: "should parse enable operation with engine path",
			fields: fields{
				FSet: flag.NewFlagSet("engine", flag.ExitOnError),
			},
			args: args{
				args: []string{"engine", "enable", "pci_dss"},
			},
			wantErr: false,
		},
		{
			name: "should parse enable operation with engine path and parameters",
			fields: fields{
				FSet: flag.NewFlagSet("engine", flag.ExitOnError),
			},
			args: args{
				args: []string{"engine", "enable", "pci_dss", "key=value"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &EngineCommand{
				FSet: tt.fields.FSet,
			}
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("EngineCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngineCommand_Handle(t *testing.T) {
	ctrl := secman.NewController(t)
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
				args: []string{"engine", "enable", "pci_dss"},
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
					Post(gomock.Any(), "sys/engines/enable/pci_dss", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle enable operation with parameters",
			args: args{
				args: []string{"engine", "enable", "pci_dss", "key=value"},
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
					Post(gomock.Any(), "sys/engines/enable/pci_dss", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle enable operation with engine not found",
			args: args{
				args: []string{"engine", "enable", "invalid_engine"},
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
					Post(gomock.Any(), "sys/engines/enable/invalid_engine", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 404,
						Body:   io.NopCloser(strings.NewReader(`{"error":"engine not found"}`)),
					}, assert.AnError)
			},
		},
		{
			name: "should handle enable operation with authentication error",
			args: args{
				args: []string{"engine", "enable", "pci_dss"},
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
			name: "should handle invalid operation",
			args: args{
				args: []string{"engine", "invalid", "pci_dss"},
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
			name: "should handle missing arguments",
			args: args{
				args: []string{"engine"},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSession := NewMockISession(ctrl)
			tt.args.o.Session = mockSession

			if tt.setup != nil {
				tt.setup(mockSession)
			}

			c := NewEngineCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("EngineCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("EngineCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
