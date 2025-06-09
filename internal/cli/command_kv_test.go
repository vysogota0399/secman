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
)

func TestNewKvCommand(t *testing.T) {
	tests := []struct {
		name string
		want *KvCommand
	}{
		{
			name: "should create new KV command",
			want: &KvCommand{
				FSet: flag.NewFlagSet("kv", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewKvCommand(); !reflect.DeepEqual(got.FSet.Name(), tt.want.FSet.Name()) {
				t.Errorf("NewKvCommand() FSet name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestKvCommand_Parse(t *testing.T) {
	type fields struct {
		FSet      *flag.FlagSet
		operation string
		key       string
		value     string
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
			name: "should parse write operation with key and value",
			fields: fields{
				FSet: flag.NewFlagSet("kv", flag.ExitOnError),
			},
			args: args{
				args: []string{"kv", "write", "-k", "test_key", "-v", "test_value"},
			},
			wantErr: false,
		},
		{
			name: "should parse read operation with key",
			fields: fields{
				FSet: flag.NewFlagSet("kv", flag.ExitOnError),
			},
			args: args{
				args: []string{"kv", "read", "-k", "test_key"},
			},
			wantErr: false,
		},
		{
			name: "should parse update operation with key and value",
			fields: fields{
				FSet: flag.NewFlagSet("kv", flag.ExitOnError),
			},
			args: args{
				args: []string{"kv", "update", "-k", "test_key"},
			},
			wantErr: false,
		},
		{
			name: "should parse delete operation with key",
			fields: fields{
				FSet: flag.NewFlagSet("kv", flag.ExitOnError),
			},
			args: args{
				args: []string{"kv", "delete", "-k", "test_key"},
			},
			wantErr: false,
		},
		{
			name: "should return error for invalid operation",
			fields: fields{
				FSet: flag.NewFlagSet("kv", flag.ExitOnError),
			},
			args: args{
				args: []string{"kv", "invalid"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &KvCommand{
				FSet:      tt.fields.FSet,
				operation: tt.fields.operation,
				key:       tt.fields.key,
				value:     tt.fields.value,
			}
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("KvCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKvCommand_Handle_Write(t *testing.T) {
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
			name: "should handle write operation successfully",
			args: args{
				args: []string{"kv", "write", "-k", "test_key", "-v", "test_value"},
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
					Post(gomock.Any(), "engine/secrets/kv", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"key":"test_key","value":"test_value"}`)),
					}, nil)
			},
		},
		{
			name: "should handle write operation with missing required fields",
			args: args{
				args: []string{"kv", "write", "-k", "test_key"},
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

			c := NewKvCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("KvCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("KvCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKvCommand_Handle_Read(t *testing.T) {
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
			name: "should handle read operation successfully",
			args: args{
				args: []string{"kv", "read", "-k", "test_key"},
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
					Get(gomock.Any(), "engine/secrets/kv/test_key", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"key":"test_key","value":"test_value"}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with server error",
			args: args{
				args: []string{"kv", "read", "-k", "test_key"},
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
					Get(gomock.Any(), "engine/secrets/kv/test_key", gomock.Any()).
					Return(&Response{
						Status: 500,
						Body:   io.NopCloser(strings.NewReader(`{"error":"internal server error"}`)),
					}, assert.AnError)
			},
		},
		{
			name: "should handle read operation with not found error",
			args: args{
				args: []string{"kv", "read", "-k", "test_key"},
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
					Get(gomock.Any(), "engine/secrets/kv/test_key", gomock.Any()).
					Return(&Response{
						Status: 404,
						Body:   io.NopCloser(strings.NewReader(`{"error":"secret not found"}`)),
					}, assert.AnError)
			},
		},
		{
			name: "should handle read operation with missing key",
			args: args{
				args: []string{"kv", "read"},
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

			c := NewKvCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("KvCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("KvCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKvCommand_Handle_Update(t *testing.T) {
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
			name: "should handle update operation successfully",
			args: args{
				args: []string{"kv", "update", "-k", "test_key", "fiz=baz"},
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
					Put(gomock.Any(), "engine/secrets/kv/test_key", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle update operation with missing key",
			args: args{
				args: []string{"kv", "update"},
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

			c := NewKvCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("KvCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("KvCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKvCommand_Handle_Delete(t *testing.T) {
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
			name: "should handle delete operation successfully",
			args: args{
				args: []string{"kv", "delete", "-k", "test_key"},
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
					Delete(gomock.Any(), "engine/secrets/kv/test_key", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle delete operation with missing key",
			args: args{
				args: []string{"kv", "delete"},
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

			c := NewKvCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("KvCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("KvCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestKvCommand_Handle_Invalid(t *testing.T) {
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
			name: "should handle invalid operation",
			args: args{
				args: []string{"kv", "invalid"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: false,
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

			c := NewKvCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("KvCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("KvCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
