package cli

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/vysogota0399/secman/internal/logging"
)

func TestNewSession(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "secman-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Override user home directory for testing
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	type args struct {
		cfg *Config
		lg  *logging.ZapLogger
	}
	tests := []struct {
		name    string
		args    args
		want    *Session
		wantErr bool
	}{
		{
			name: "successful session creation",
			args: args{
				cfg: &Config{
					RootToken: "test-token",
				},
				lg: &logging.ZapLogger{},
			},
			want: &Session{
				Secrets:      make(map[string]string),
				storagePath:  filepath.Join(tmpDir, ".secman"),
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			wantErr: false,
		},
		{
			name: "successful session creation without root token",
			args: args{
				cfg: &Config{},
				lg:  &logging.ZapLogger{},
			},
			want: &Session{
				Secrets:     make(map[string]string),
				storagePath: filepath.Join(tmpDir, ".secman"),
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewSession(tt.args.cfg, tt.args.lg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Compare fields individually since some fields might be initialized differently
				if got.storagePath != tt.want.storagePath {
					t.Errorf("NewSession().storagePath = %v, want %v", got.storagePath, tt.want.storagePath)
				}
				if got.AuthProvider != tt.want.AuthProvider {
					t.Errorf("NewSession().AuthProvider = %v, want %v", got.AuthProvider, tt.want.AuthProvider)
				}
				if len(got.providers) != len(tt.want.providers) {
					t.Errorf("NewSession().providers length = %v, want %v", len(got.providers), len(tt.want.providers))
				}
				if got.Secrets == nil {
					t.Error("NewSession().Secrets is nil")
				}
				if got.lg == nil {
					t.Error("NewSession().lg is nil")
				}

				// Verify that the root token is set correctly when provided
				if tt.args.cfg.RootToken != "" {
					if value, ok := got.Get("root_token"); !ok || value != tt.args.cfg.RootToken {
						t.Errorf("NewSession() root token = %v, want %v", value, tt.args.cfg.RootToken)
					}
				}
			}
		})
	}
}

func TestSession_Init(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "secman-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Override user home directory for testing
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Initialize logger
	lg, err := logging.MustZapLogger(&Config{LogLevel: -1})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "successful initialization of new session",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           lg,
				storagePath:  filepath.Join(tmpDir, ".secman"),
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr: false,
		},
		{
			name: "successful initialization of existing session",
			fields: fields{
				Secrets: map[string]string{
					"test-key": "test-value",
				},
				lg:           lg,
				storagePath:  filepath.Join(tmpDir, ".secman"),
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}

			// For the second test case, we need to create the session file first
			if tt.name == "successful initialization of existing session" {
				if err := s.Persist(); err != nil {
					t.Fatalf("Failed to persist session: %v", err)
				}
			}

			if err := s.Init(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Session.Init() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify that the session file exists
			if _, err := os.Stat(s.storagePath); os.IsNotExist(err) {
				t.Error("Session file was not created")
			}
		})
	}
}

func TestSession_Persist(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "secman-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Override user home directory for testing
	originalHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", originalHome)

	// Initialize logger
	lg, err := logging.MustZapLogger(&Config{LogLevel: -1})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "successful persist of empty session",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           lg,
				storagePath:  filepath.Join(tmpDir, ".secman"),
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			wantErr: false,
		},
		{
			name: "successful persist of session with data",
			fields: fields{
				Secrets: map[string]string{
					"test-key": "test-value",
				},
				lg:           lg,
				storagePath:  filepath.Join(tmpDir, ".secman"),
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			if err := s.Persist(); (err != nil) != tt.wantErr {
				t.Errorf("Session.Persist() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify that the session file exists
			if _, err := os.Stat(s.storagePath); os.IsNotExist(err) {
				t.Error("Session file was not created")
			}

			// For the second test case, verify that the data was persisted correctly
			if tt.name == "successful persist of session with data" {
				// Initialize a new session to read the persisted data
				newSession := &Session{
					Secrets:      make(map[string]string),
					lg:           tt.fields.lg,
					storagePath:  tt.fields.storagePath,
					AuthProvider: tt.fields.AuthProvider,
					providers:    tt.fields.providers,
				}
				if err := newSession.Init(context.Background()); err != nil {
					t.Fatalf("Failed to initialize session: %v", err)
				}

				// Verify that the data was persisted correctly
				if value, ok := newSession.Get("test-key"); !ok || value != "test-value" {
					t.Errorf("Persisted data mismatch: got %v, want %v", value, "test-value")
				}
			}
		})
	}
}

func TestSession_GetSecrets(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]string
	}{
		{
			name: "get empty secrets",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			want: make(map[string]string),
		},
		{
			name: "get secrets with data",
			fields: fields{
				Secrets: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			want: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			if got := s.GetSecrets(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Session.GetSecrets() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSession_Set(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]string
	}{
		{
			name: "set new key-value pair",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				key:   "test-key",
				value: "test-value",
			},
			want: map[string]string{
				"test-key": "test-value",
			},
		},
		{
			name: "overwrite existing key-value pair",
			fields: fields{
				Secrets: map[string]string{
					"test-key": "old-value",
				},
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				key:   "test-key",
				value: "new-value",
			},
			want: map[string]string{
				"test-key": "new-value",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			s.Set(tt.args.key, tt.args.value)
			if !reflect.DeepEqual(s.Secrets, tt.want) {
				t.Errorf("Session.Set() = %v, want %v", s.Secrets, tt.want)
			}
		})
	}
}

func TestSession_Get(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	type args struct {
		key string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
		want1  bool
	}{
		{
			name: "get existing key",
			fields: fields{
				Secrets: map[string]string{
					"test-key": "test-value",
				},
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				key: "test-key",
			},
			want:  "test-value",
			want1: true,
		},
		{
			name: "get non-existent key",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				key: "non-existent-key",
			},
			want:  "",
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			got, got1 := s.Get(tt.args.key)
			if got != tt.want {
				t.Errorf("Session.Get() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Session.Get() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestSession_Authenticate(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	type args struct {
		h map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "successful authentication with root token",
			fields: fields{
				Secrets: map[string]string{
					"root_token": "test-token",
				},
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				h: make(map[string]string),
			},
			wantErr: false,
		},
		{
			name: "successful authentication with logopass",
			fields: fields{
				Secrets: map[string]string{
					"engine/auth/logopass/login/token": "test-token",
				},
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "logopass",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				h: make(map[string]string),
			},
			wantErr: false,
		},
		{
			name: "error when no auth provider selected",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				h: make(map[string]string),
			},
			wantErr: true,
		},
		{
			name: "error when token not found",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				h: make(map[string]string),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			if err := s.Authenticate(tt.args.h); (err != nil) != tt.wantErr {
				t.Errorf("Session.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}

			// For successful cases, verify that the headers were set correctly
			if !tt.wantErr {
				if tt.fields.AuthProvider == "root_token" {
					if tt.args.h["X-Secman-Token"] != "test-token" {
						t.Errorf("X-Secman-Token header = %v, want %v", tt.args.h["X-Secman-Token"], "test-token")
					}
				} else if tt.fields.AuthProvider == "logopass" {
					if tt.args.h["Authorization"] != "Bearer test-token" {
						t.Errorf("Authorization header = %v, want %v", tt.args.h["Authorization"], "Bearer test-token")
					}
				}
			}
		})
	}
}

func TestSession_Login(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	type args struct {
		token    string
		provider string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]string
	}{
		{
			name: "login with root token",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				token:    "test-token",
				provider: "root_token",
			},
			want: map[string]string{
				"root_token": "test-token",
			},
		},
		{
			name: "login with logopass",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				token:    "test-token",
				provider: "logopass",
			},
			want: map[string]string{
				"engine/auth/logopass/login/token": "test-token",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			s.Login(tt.args.token, tt.args.provider)

			// Verify that the auth provider was set
			if s.AuthProvider != tt.args.provider {
				t.Errorf("Session.AuthProvider = %v, want %v", s.AuthProvider, tt.args.provider)
			}

			// Verify that the token was stored correctly
			if !reflect.DeepEqual(s.Secrets, tt.want) {
				t.Errorf("Session.Secrets = %v, want %v", s.Secrets, tt.want)
			}
		})
	}
}

func TestSession_Clear(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]string
	}{
		{
			name: "clear empty session",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			want: make(map[string]string),
		},
		{
			name: "clear session with data",
			fields: fields{
				Secrets: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			want: make(map[string]string),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			s.Clear()
			if !reflect.DeepEqual(s.Secrets, tt.want) {
				t.Errorf("Session.Clear() = %v, want %v", s.Secrets, tt.want)
			}
		})
	}
}

func TestSession_GetAuthProvider(t *testing.T) {
	type fields struct {
		Secrets      map[string]string
		lg           *logging.ZapLogger
		storagePath  string
		AuthProvider string
		providers    map[string]AuthProvider
	}
	type args struct {
		ap string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   AuthProvider
	}{
		{
			name: "get root token auth provider",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				ap: "root_token",
			},
			want: NewRootTokenAuthProvider(),
		},
		{
			name: "get logopass auth provider",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "logopass",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				ap: "logopass",
			},
			want: NewLogopassAuthProvider(),
		},
		{
			name: "get non-existent auth provider",
			fields: fields{
				Secrets:      make(map[string]string),
				lg:           &logging.ZapLogger{},
				storagePath:  "/tmp/.secman",
				AuthProvider: "root_token",
				providers: map[string]AuthProvider{
					"root_token": NewRootTokenAuthProvider(),
					"logopass":   NewLogopassAuthProvider(),
				},
			},
			args: args{
				ap: "non-existent",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Session{
				Secrets:      tt.fields.Secrets,
				lg:           tt.fields.lg,
				storagePath:  tt.fields.storagePath,
				AuthProvider: tt.fields.AuthProvider,
				providers:    tt.fields.providers,
			}
			got := s.GetAuthProvider(tt.args.ap)
			if tt.want == nil {
				if got != nil {
					t.Errorf("Session.GetAuthProvider() = %v, want %v", got, tt.want)
				}
			} else {
				// Compare the type of the provider since we can't compare the actual instances
				if reflect.TypeOf(got) != reflect.TypeOf(tt.want) {
					t.Errorf("Session.GetAuthProvider() = %T, want %T", got, tt.want)
				}
			}
		})
	}
}
