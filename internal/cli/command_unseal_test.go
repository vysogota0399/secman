package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewUnsealCommand(t *testing.T) {
	tests := []struct {
		name string
		want *UnsealCommand
	}{
		{
			name: "create new unseal command",
			want: &UnsealCommand{
				FSet: flag.NewFlagSet("unseal", flag.ExitOnError),
				key:  "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewUnsealCommand()
			assert.Equal(t, tt.want.FSet.Name(), got.FSet.Name())
			assert.Equal(t, tt.want.key, got.key)
		})
	}
}

func TestUnsealCommand_Parse(t *testing.T) {
	type args struct {
		args []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "parse with valid key",
			args: args{
				args: []string{"unseal", "-k", "test-key"},
			},
			wantErr: false,
		},
		{
			name: "parse with missing key",
			args: args{
				args: []string{"unseal"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewUnsealCommand()
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("UnsealCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnsealCommand_Handle(t *testing.T) {
	ctrl := NewController(t)

	mockSession := NewMockISession(ctrl)
	mockClient := NewMockIClient(ctrl)
	mockAuthProvider := NewMockAuthProvider(ctrl)
	type fields struct {
		key string
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
		wantErr bool
		setup   func()
	}{
		{
			name: "successful unseal",
			fields: fields{
				key: "test-key",
			},
			args: args{
				ctx: context.Background(),
				b:   &strings.Builder{},
				o: &Operation{
					Session: mockSession,
					Client:  mockClient,
				},
			},
			wantErr: false,
			setup: func() {
				// Setup root token auth provider
				mockSession.EXPECT().
					GetAuthProvider("root_token").
					Return(mockAuthProvider)

				mockAuthProvider.EXPECT().
					GetToken(mockSession).
					Return("root-token", true)

				mockSession.EXPECT().
					Login("root-token", "root_token")

				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				// Setup unseal request
				unsealPayload := map[string]string{
					"key": "test-key",
				}
				payload, _ := json.Marshal(unsealPayload)

				mockClient.EXPECT().
					Post(gomock.Any(), "sys/unseal", bytes.NewReader(payload), gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Body:   strings.NewReader(`{"message": "success"}`),
					}, nil)

				// Setup status check
				mockClient.EXPECT().
					Get(gomock.Any(), "sys/status", gomock.Any()).
					Return(&Response{
						Status: http.StatusOK,
						Body:   strings.NewReader(`{"barrier": "test-barrier", "sealed": false}`),
					}, nil)
			},
		},
		{
			name: "missing root token",
			args: args{
				ctx: context.Background(),
				b:   &strings.Builder{},
				o: &Operation{
					Session: mockSession,
					Client:  mockClient,
				},
			},
			fields: fields{
				key: "invalid-key",
			},
			wantErr: true,
			setup: func() {
				mockSession.EXPECT().
					GetAuthProvider("root_token").
					Return(mockAuthProvider)

				mockAuthProvider.EXPECT().
					GetToken(mockSession).
					Return("", false)
			},
		},
		{
			name: "invalid unseal key",
			fields: fields{
				key: "invalid-key",
			},
			args: args{
				ctx: context.Background(),
				b:   &strings.Builder{},
				o: &Operation{
					Session: mockSession,
					Client:  mockClient,
				},
			},
			wantErr: true,
			setup: func() {
				mockSession.EXPECT().
					GetAuthProvider("root_token").
					Return(mockAuthProvider)

				mockAuthProvider.EXPECT().
					GetToken(mockSession).
					Return("root-token", true)

				mockSession.EXPECT().
					Login("root-token", "root_token")

				mockSession.EXPECT().
					Authenticate(gomock.Any()).
					Return(nil)

				unsealPayload := map[string]string{
					"key": "invalid-key",
				}
				payload, _ := json.Marshal(unsealPayload)

				mockClient.EXPECT().
					Post(gomock.Any(), "sys/unseal", bytes.NewReader(payload), gomock.Any()).
					Return(&Response{
						Status: http.StatusBadRequest,
						Body:   strings.NewReader(`{"error": "invalid unseal key"}`),
					}, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			c := NewUnsealCommand()

			c.key = tt.fields.key
			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("UnsealCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
