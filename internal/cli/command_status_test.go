package cli

import (
	"bytes"
	"context"
	"flag"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewStatusCommand(t *testing.T) {
	tests := []struct {
		name string
		want *StatusCommand
	}{
		{
			name: "creates new status command",
			want: &StatusCommand{
				FSet: flag.NewFlagSet("status", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewStatusCommand()
			if got.FSet.Name() != tt.want.FSet.Name() {
				t.Errorf("NewStatusCommand() FSet.Name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestStatusCommand_Handle(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockClient := NewMockIClient(ctrl)

	type fields struct {
		FSet *flag.FlagSet
	}
	type args struct {
		ctx context.Context
		b   *strings.Builder
		o   *Operation
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		setup   func()
		wantErr bool
	}{
		{
			name: "handles status command successfully",
			fields: fields{
				FSet: flag.NewFlagSet("status", flag.ExitOnError),
			},
			args: args{
				ctx: context.Background(),
				b:   &strings.Builder{},
				o: &Operation{
					Session: mockSession,
					Client:  mockClient,
				},
			},
			setup: func() {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				statusResponse := `{"barrier":"shamir","initialized":true,"sealed":false}`
				body := bytes.NewBufferString(statusResponse)
				mockClient.EXPECT().
					Get(gomock.Any(), "sys/status", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   body,
					}, nil)
			},
			wantErr: false,
		},
		{
			name: "handles unauthorized error",
			fields: fields{
				FSet: flag.NewFlagSet("status", flag.ExitOnError),
			},
			args: args{
				ctx: context.Background(),
				b:   &strings.Builder{},
				o: &Operation{
					Session: mockSession,
					Client:  mockClient,
				},
			},
			setup: func() {
				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				mockClient.EXPECT().
					Get(gomock.Any(), "sys/status", gomock.Any()).
					Return(&Response{Status: 401}, assert.AnError)
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := &StatusCommand{
				FSet: tt.fields.FSet,
			}
			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("StatusCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
