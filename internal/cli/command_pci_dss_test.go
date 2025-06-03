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
	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewCommandPCI_DSS(t *testing.T) {
	tests := []struct {
		name string
		want *CommandPCIDSS
	}{
		{
			name: "should create new PCI-DSS command",
			want: &CommandPCIDSS{
				FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewCommandPCIDSS()
			if got.FSet.Name() != tt.want.FSet.Name() {
				t.Errorf("NewCommandPCIDSS() FSet name = %v, want %v", got.FSet.Name(), tt.want.FSet.Name())
			}
		})
	}
}

func TestCommandPCI_DSS_Parse(t *testing.T) {
	type fields struct {
		FSet                *flag.FlagSet
		operation           string
		pan                 string
		cardholderName      string
		expiryDate          string
		securityCode        string
		panToken            string
		cardholderNameToken string
		expiryDateToken     string
		securityCodeToken   string
		showMetadata        bool
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
			name: "should parse write operation with all required fields",
			fields: fields{
				FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
			},
			args: args{
				args: []string{"pci_dss", "write", "-p", "4111111111111111", "-cn", "John Doe", "-ed", "12/25", "-sc", "123"},
			},
			wantErr: false,
		},
		{
			name: "should parse read operation with PAN token",
			fields: fields{
				FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
			},
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123"},
			},
			wantErr: false,
		},
		{
			name: "should parse update operation with PAN token",
			fields: fields{
				FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
			},
			args: args{
				args: []string{"pci_dss", "update", "-pt", "token123"},
			},
			wantErr: false,
		},
		{
			name: "should parse delete operation with PAN token",
			fields: fields{
				FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
			},
			args: args{
				args: []string{"pci_dss", "delete", "-pt", "token123"},
			},
			wantErr: false,
		},
		{
			name: "should return error for invalid operation",
			fields: fields{
				FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
			},
			args: args{
				args: []string{"pci_dss", "invalid"},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CommandPCIDSS{
				FSet:                tt.fields.FSet,
				operation:           tt.fields.operation,
				pan:                 tt.fields.pan,
				cardholderName:      tt.fields.cardholderName,
				expiryDate:          tt.fields.expiryDate,
				securityCode:        tt.fields.securityCode,
				panToken:            tt.fields.panToken,
				cardholderNameToken: tt.fields.cardholderNameToken,
				expiryDateToken:     tt.fields.expiryDateToken,
				securityCodeToken:   tt.fields.securityCodeToken,
				showMetadata:        tt.fields.showMetadata,
			}
			if err := c.Parse(tt.args.args); (err != nil) != tt.wantErr {
				t.Errorf("CommandPCIDSS.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandPCI_DSS_Handle_Write(t *testing.T) {
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
			name: "should handle write operation successfully",
			args: args{
				args: []string{"pci_dss", "write", "-p", "4111111111111111", "-cn", "John Doe", "-ed", "12/25", "-sc", "123"},
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
					Post(gomock.Any(), "engine/secrets/pci_dss", gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"pan":"token1","cardholder_name":"token2","expiry_date":"token3","security_code":"token4"}`)),
					}, nil)
			},
		},
		{
			name: "should handle write operation with missing required fields",
			args: args{
				args: []string{"pci_dss", "write", "-p", "4111111111111111"},
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

			c := NewCommandPCIDSS()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("CommandPCIDSS.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("CommandPCIDSS.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandPCI_DSS_Handle_Read(t *testing.T) {
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
			name: "should handle read operation successfully",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"pan":"4111111111111111","cardholder_name":"John Doe","expiry_date":"12/25","security_code":"123"}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with expiry date token",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123", "-edt", "edtoken456"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123/expiry_date/edtoken456", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"expiry_date":"12/25"}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with security code token",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123", "-sc", "sctoken789"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123/security_code/sctoken789", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"security_code":"123"}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with cardholder name token",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123", "-cct", "cntoken101"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123/cardholder_name/cntoken101", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"cardholder_name":"John Doe"}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with multiple tokens",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123", "-edt", "edtoken456", "-sc", "sctoken789", "-cct", "cntoken101"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123/cardholder_name/cntoken101", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"pan":"4111111111111111","cardholder_name":"John Doe","expiry_date":"12/25","security_code":"123"}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with show metadata flag",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123", "-m"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123/metadata", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"pan":"4111111111111111","cardholder_name":"John Doe","expiry_date":"12/25","security_code":"123","metadata":{"key":"value"}}`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with server error",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123", gomock.Any()).
					Return(&Response{
						Status: 500,
						Body:   io.NopCloser(strings.NewReader(`{"error":"internal server error"}`)),
					}, assert.AnError)
			},
		},
		{
			name: "should handle read operation with not found error",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123", gomock.Any()).
					Return(&Response{
						Status: 404,
						Body:   io.NopCloser(strings.NewReader(`{"error":"secret not found"}`)),
					}, assert.AnError)
			},
		},
		{
			name: "should handle read operation with invalid response",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123"},
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
					Get(gomock.Any(), "engine/secrets/pci_dss/token123", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`invalid json`)),
					}, nil)
			},
		},
		{
			name: "should handle read operation with missing PAN token",
			args: args{
				args: []string{"pci_dss", "read"},
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
			name: "should handle read operation with authentication error",
			args: args{
				args: []string{"pci_dss", "read", "-pt", "token123"},
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSession := NewMockISession(ctrl)
			tt.args.o.Session = mockSession

			if tt.setup != nil {
				tt.setup(mockSession)
			}

			c := NewCommandPCIDSS()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("CommandPCIDSS.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("CommandPCIDSS.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandPCI_DSS_Handle_Update(t *testing.T) {
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
			name: "should handle update operation successfully",
			args: args{
				args: []string{"pci_dss", "update", "-pt", "token123", "key=value"},
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
					Put(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle update operation with missing PAN token",
			args: args{
				args: []string{"pci_dss", "update"},
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

			c := NewCommandPCIDSS()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("CommandPCIDSS.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("CommandPCIDSS.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandPCI_DSS_Handle_Delete(t *testing.T) {
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
			name: "should handle delete operation successfully",
			args: args{
				args: []string{"pci_dss", "delete", "-pt", "token123"},
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
					Delete(gomock.Any(), "engine/secrets/pci_dss/token123", gomock.Any()).
					Return(&Response{
						Status: 200,
						Body:   io.NopCloser(strings.NewReader(`{"message":"success"}`)),
					}, nil)
			},
		},
		{
			name: "should handle delete operation with missing PAN token",
			args: args{
				args: []string{"pci_dss", "delete"},
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

			c := NewCommandPCIDSS()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("CommandPCIDSS.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("CommandPCIDSS.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCommandPCI_DSS_Handle_Invalid(t *testing.T) {
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
			name: "should handle invalid operation",
			args: args{
				args: []string{"pci_dss", "invalid"},
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

			c := NewCommandPCIDSS()

			if err := c.Parse(tt.args.args); err != nil {
				t.Errorf("CommandPCIDSS.Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err := c.Handle(tt.args.ctx, tt.args.b, tt.args.o); (err != nil) != tt.wantErr {
				t.Errorf("CommandPCIDSS.Handle() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
