package cli

import (
	"os"
	"reflect"
	"testing"
)

func TestNewConfig(t *testing.T) {
	// Save original env vars
	originalEnv := make(map[string]string)
	for _, key := range []string{"SERVER_URL", "ROOT_TOKEN", "LOG_LEVEL", "SSL_SKIP_VERIFY"} {
		if val, exists := os.LookupEnv(key); exists {
			originalEnv[key] = val
		}
	}

	// Cleanup function to restore original env vars
	defer func() {
		for key, val := range originalEnv {
			os.Setenv(key, val)
		}
		for _, key := range []string{"SERVER_URL", "ROOT_TOKEN", "LOG_LEVEL", "SSL_SKIP_VERIFY"} {
			if _, exists := originalEnv[key]; !exists {
				os.Unsetenv(key)
			}
		}
	}()

	tests := []struct {
		name    string
		env     map[string]string
		want    *Config
		wantErr bool
	}{
		{
			name: "successful config creation with all fields",
			env: map[string]string{
				"SERVER_URL":      "http://localhost:8080",
				"ROOT_TOKEN":      "test-token",
				"LOG_LEVEL":       "1",
				"SSL_SKIP_VERIFY": "true",
			},
			want: &Config{
				ServerURL:     "http://localhost:8080",
				RootToken:     "test-token",
				LogLevel:      1,
				SSLSkipVerify: true,
			},
			wantErr: false,
		},
		{
			name: "successful config creation with defaults",
			env: map[string]string{
				"SERVER_URL": "http://localhost:8080",
			},
			want: &Config{
				ServerURL:     "http://localhost:8080",
				RootToken:     "",
				LogLevel:      0,
				SSLSkipVerify: false,
			},
			wantErr: false,
		},
		{
			name: "config with empty server URL",
			env: map[string]string{
				"SERVER_URL": "",
			},
			want: &Config{
				ServerURL:     "",
				RootToken:     "",
				LogLevel:      0,
				SSLSkipVerify: false,
			},
			wantErr: false,
		},
		{
			name: "error when log level is invalid",
			env: map[string]string{
				"SERVER_URL": "http://localhost:8080",
				"LOG_LEVEL":  "invalid",
			},
			want: &Config{
				ServerURL:     "http://localhost:8080",
				RootToken:     "",
				SSLSkipVerify: false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all environment variables first
			for _, key := range []string{"SERVER_URL", "ROOT_TOKEN", "LOG_LEVEL", "SSL_SKIP_VERIFY"} {
				os.Unsetenv(key)
			}

			// Set up environment variables for the test
			for key, val := range tt.env {
				os.Setenv(key, val)
			}

			got, err := NewConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}
