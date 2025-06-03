package cli

import (
	"reflect"
	"testing"

	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewLogopassAuthProvider(t *testing.T) {
	tests := []struct {
		name string
		want *LogopassAuthProvider
	}{
		{
			name: "creates new logopass auth provider",
			want: &LogopassAuthProvider{
				tokenPath: "engine/auth/logopass/login/token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewLogopassAuthProvider(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLogopassAuthProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogopassAuthProvider_Authenticate(t *testing.T) {
	ctrl := secman.NewController(t)

	mockSession := NewMockISession(ctrl)

	type fields struct {
		tokenPath string
	}
	type args struct {
		h       map[string]string
		session ISession
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		setup   func()
	}{
		{
			name: "successful authentication",
			fields: fields{
				tokenPath: "engine/auth/logopass/login/token",
			},
			args: args{
				h:       make(map[string]string),
				session: mockSession,
			},
			wantErr: false,
			setup: func() {
				mockSession.EXPECT().
					Get("engine/auth/logopass/login/token").
					Return("test-token", true)
			},
		},
		{
			name: "no token found",
			fields: fields{
				tokenPath: "engine/auth/logopass/login/token",
			},
			args: args{
				h:       make(map[string]string),
				session: mockSession,
			},
			wantErr: true,
			setup: func() {
				mockSession.EXPECT().
					Get("engine/auth/logopass/login/token").
					Return("", false)
			},
		},
		{
			name: "empty token",
			fields: fields{
				tokenPath: "engine/auth/logopass/login/token",
			},
			args: args{
				h:       make(map[string]string),
				session: mockSession,
			},
			wantErr: true,
			setup: func() {
				mockSession.EXPECT().
					Get("engine/auth/logopass/login/token").
					Return("", true)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &LogopassAuthProvider{
				tokenPath: tt.fields.tokenPath,
			}
			if tt.setup != nil {
				tt.setup()
			}
			if err := a.Authenticate(tt.args.h, tt.args.session); (err != nil) != tt.wantErr {
				t.Errorf("LogopassAuthProvider.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.args.h["Authorization"] != "Bearer test-token" {
				t.Errorf("LogopassAuthProvider.Authenticate() header = %v, want %v", tt.args.h["Authorization"], "Bearer test-token")
			}
		})
	}
}

func TestLogopassAuthProvider_Login(t *testing.T) {
	ctrl := secman.NewController(t)

	mockSession := NewMockISession(ctrl)

	type fields struct {
		tokenPath string
	}
	type args struct {
		session ISession
		token   string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		setup  func()
	}{
		{
			name: "successful login",
			fields: fields{
				tokenPath: "engine/auth/logopass/login/token",
			},
			args: args{
				session: mockSession,
				token:   "test-token",
			},
			setup: func() {
				mockSession.EXPECT().
					Set("engine/auth/logopass/login/token", "test-token")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &LogopassAuthProvider{
				tokenPath: tt.fields.tokenPath,
			}
			if tt.setup != nil {
				tt.setup()
			}
			a.Login(tt.args.session, tt.args.token)
		})
	}
}

func TestLogopassAuthProvider_GetToken(t *testing.T) {
	ctrl := secman.NewController(t)

	mockSession := NewMockISession(ctrl)

	type fields struct {
		tokenPath string
	}
	type args struct {
		session ISession
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		want1  bool
		setup  func()
	}{
		{
			name: "token exists",
			fields: fields{
				tokenPath: "engine/auth/logopass/login/token",
			},
			args: args{
				session: mockSession,
			},
			want:  "test-token",
			want1: true,
			setup: func() {
				mockSession.EXPECT().
					Get("engine/auth/logopass/login/token").
					Return("test-token", true)
			},
		},
		{
			name: "token does not exist",
			fields: fields{
				tokenPath: "engine/auth/logopass/login/token",
			},
			args: args{
				session: mockSession,
			},
			want:  "",
			want1: false,
			setup: func() {
				mockSession.EXPECT().
					Get("engine/auth/logopass/login/token").
					Return("", false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &LogopassAuthProvider{
				tokenPath: tt.fields.tokenPath,
			}
			if tt.setup != nil {
				tt.setup()
			}
			got, got1 := a.GetToken(tt.args.session)
			if got != tt.want {
				t.Errorf("LogopassAuthProvider.GetToken() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("LogopassAuthProvider.GetToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestNewRootTokenAuthProvider(t *testing.T) {
	tests := []struct {
		name string
		want *RootTokenAuthProvider
	}{
		{
			name: "creates new root token auth provider",
			want: &RootTokenAuthProvider{
				tokenPath: "root_token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRootTokenAuthProvider(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRootTokenAuthProvider() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRootTokenAuthProvider_Authenticate(t *testing.T) {
	ctrl := secman.NewController(t)

	mockSession := NewMockISession(ctrl)

	type fields struct {
		tokenPath string
	}
	type args struct {
		h       map[string]string
		session ISession
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		setup   func()
	}{
		{
			name: "successful authentication",
			fields: fields{
				tokenPath: "root_token",
			},
			args: args{
				h:       make(map[string]string),
				session: mockSession,
			},
			wantErr: false,
			setup: func() {
				mockSession.EXPECT().
					Get("root_token").
					Return("test-token", true)
			},
		},
		{
			name: "no token found",
			fields: fields{
				tokenPath: "root_token",
			},
			args: args{
				h:       make(map[string]string),
				session: mockSession,
			},
			wantErr: true,
			setup: func() {
				mockSession.EXPECT().
					Get("root_token").
					Return("", false)
			},
		},
		{
			name: "empty token",
			fields: fields{
				tokenPath: "root_token",
			},
			args: args{
				h:       make(map[string]string),
				session: mockSession,
			},
			wantErr: true,
			setup: func() {
				mockSession.EXPECT().
					Get("root_token").
					Return("", true)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &RootTokenAuthProvider{
				tokenPath: tt.fields.tokenPath,
			}
			if tt.setup != nil {
				tt.setup()
			}
			if err := a.Authenticate(tt.args.h, tt.args.session); (err != nil) != tt.wantErr {
				t.Errorf("RootTokenAuthProvider.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && tt.args.h["X-Secman-Token"] != "test-token" {
				t.Errorf("RootTokenAuthProvider.Authenticate() header = %v, want %v", tt.args.h["X-Secman-Token"], "test-token")
			}
		})
	}
}

func TestRootTokenAuthProvider_Login(t *testing.T) {
	ctrl := secman.NewController(t)

	mockSession := NewMockISession(ctrl)

	type fields struct {
		tokenPath string
	}
	type args struct {
		session ISession
		token   string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		setup  func()
	}{
		{
			name: "successful login",
			fields: fields{
				tokenPath: "root_token",
			},
			args: args{
				session: mockSession,
				token:   "test-token",
			},
			setup: func() {
				mockSession.EXPECT().
					Set("root_token", "test-token")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &RootTokenAuthProvider{
				tokenPath: tt.fields.tokenPath,
			}
			if tt.setup != nil {
				tt.setup()
			}
			a.Login(tt.args.session, tt.args.token)
		})
	}
}

func TestRootTokenAuthProvider_GetToken(t *testing.T) {
	ctrl := secman.NewController(t)

	mockSession := NewMockISession(ctrl)

	type fields struct {
		tokenPath string
	}
	type args struct {
		session ISession
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		want1  bool
		setup  func()
	}{
		{
			name: "token exists",
			fields: fields{
				tokenPath: "root_token",
			},
			args: args{
				session: mockSession,
			},
			want:  "test-token",
			want1: true,
			setup: func() {
				mockSession.EXPECT().
					Get("root_token").
					Return("test-token", true)
			},
		},
		{
			name: "token does not exist",
			fields: fields{
				tokenPath: "root_token",
			},
			args: args{
				session: mockSession,
			},
			want:  "",
			want1: false,
			setup: func() {
				mockSession.EXPECT().
					Get("root_token").
					Return("", false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &RootTokenAuthProvider{
				tokenPath: tt.fields.tokenPath,
			}
			if tt.setup != nil {
				tt.setup()
			}
			got, got1 := a.GetToken(tt.args.session)
			if got != tt.want {
				t.Errorf("RootTokenAuthProvider.GetToken() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("RootTokenAuthProvider.GetToken() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
