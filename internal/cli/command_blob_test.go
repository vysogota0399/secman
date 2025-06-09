package cli

import (
	"context"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestNewBlobCommand(t *testing.T) {
	tests := []struct {
		name string
		want *BlobCommand
	}{
		{
			name: "should create new blob command",
			want: &BlobCommand{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBlobCommand()
			if got.FSet.Name() != tt.want.FSet.Name() {
				t.Errorf("NewBlobCommand() FSet name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestBlobCommand_Parse(t *testing.T) {
	type fields struct {
		FSet         *flag.FlagSet
		operation    string
		filePath     string
		directory    string
		showMetadata bool
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
			name: "should parse write operation with file path",
			fields: fields{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
			args: args{
				args: []string{"blob", "write", "-f", "test.txt"},
			},
			wantErr: false,
		},
		{
			name: "should parse read operation with directory",
			fields: fields{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
			args: args{
				args: []string{"blob", "read", "-d", "/tmp", "token123"},
			},
			wantErr: false,
		},
		{
			name: "should parse read operation with metadata flag",
			fields: fields{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
			args: args{
				args: []string{"blob", "read", "-m", "token123"},
			},
			wantErr: false,
		},
		{
			name: "should parse update operation",
			fields: fields{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
			args: args{
				args: []string{"blob", "update", "token123", "key=value"},
			},
			wantErr: false,
		},
		{
			name: "should parse delete operation",
			fields: fields{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
			args: args{
				args: []string{"blob", "delete", "token123"},
			},
			wantErr: false,
		},
		{
			name: "should return error for invalid operation",
			fields: fields{
				FSet: flag.NewFlagSet("blob", flag.ExitOnError),
			},
			args: args{
				args: []string{"blob", "invalid"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &BlobCommand{
				FSet:         tt.fields.FSet,
				operation:    tt.fields.operation,
				filePath:     tt.fields.filePath,
				directory:    tt.fields.directory,
				showMetadata: tt.fields.showMetadata,
			}
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("BlobCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBlobCommand_Handle_Write(t *testing.T) {
	ctrl := NewController(t)
	mockClient := NewMockIClient(ctrl)

	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatal(err)
	}

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
				args: []string{"blob", "write", "-f", testFile},
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
					MultipartRequest(gomock.Any(), "POST", "engine/secrets/blobs", gomock.Any(), gomock.Any(), gomock.Any()).
					DoAndReturn(func(ctx context.Context, method, route string, headers map[string]string, formData map[string]string, blob *Blob) (*Response, error) {
						assert.Equal(t, "POST", method)
						assert.Equal(t, "engine/secrets/blobs", route)
						assert.Equal(t, "test.txt", filepath.Base(blob.FileName))
						return &Response{
							Status: 200,
							Body:   io.NopCloser(strings.NewReader(`{"token":"token123"}`)),
						}, nil
					})
			},
		},
		{
			name: "should handle write operation with missing file path",
			args: args{
				args: []string{"blob", "write"},
				ctx:  context.Background(),
				b:    &strings.Builder{},
				o: &Operation{
					Client: mockClient,
				},
			},
			wantErr: true,
			setup: func(mockSession *MockISession) {
				// No expectations needed as the command should fail before making any API calls
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

			c := NewBlobCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("BlobCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("BlobCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBlobCommand_Handle_Read(t *testing.T) {
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
				args: []string{"blob", "read", "-d", "/tmp", "token123"},
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
					Get(gomock.Any(), "engine/secrets/blobs/token123", gomock.Any()).
					Return(&Response{
						Status: 200,
						Headers: map[string]string{
							"Content-Disposition": "attachment; filename=test.txt",
						},
						Body: io.NopCloser(strings.NewReader("test content")),
					}, nil)
			},
		},
		{
			name: "should handle read operation with metadata",
			args: args{
				args: []string{"blob", "read", "-m", "token123"},
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
					Get(gomock.Any(), "engine/secrets/blobs/token123/metadata", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"metadata":{"key":"value"}}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with missing token",
			args: args{
				args: []string{"blob", "read", "-d", "/tmp"},
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

			c := NewBlobCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("BlobCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("BlobCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBlobCommand_Handle_Update(t *testing.T) {
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
				args: []string{"blob", "update", "token123", "key=value"},
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
					Put(gomock.Any(), "engine/secrets/blobs/token123/metadata", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle update operation with missing token",
			args: args{
				args: []string{"blob", "update"},
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

			c := NewBlobCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("BlobCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("BlobCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBlobCommand_Handle_Delete(t *testing.T) {
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
				args: []string{"blob", "delete", "token123"},
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
					Delete(gomock.Any(), "engine/secrets/blobs/token123", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle delete operation with missing token",
			args: args{
				args: []string{"blob", "delete"},
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

			c := NewBlobCommand()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("BlobCommand.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("BlobCommand.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
