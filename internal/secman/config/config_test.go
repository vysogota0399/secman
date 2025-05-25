package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestNewConfig(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "config_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test config file
	testConfigPath := filepath.Join(tmpDir, "config.yml")
	testConfig := []byte(`
log_level: 2
server:
  address: "localhost:8080"
storage:
  type: "file"
`)
	if err := os.WriteFile(testConfigPath, testConfig, 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	// Save original env vars and restore them after the test
	originalPath := os.Getenv("FILE_STORAGE_PATH")
	defer os.Setenv("FILE_STORAGE_PATH", originalPath)

	tests := []struct {
		name    string
		envVars map[string]string
		want    *Config
		wantErr bool
	}{
		{
			name: "default configuration",
			want: &Config{
				FileStoragePath: "config.yml",
				LogLevel:        -1,
				Server: Server{
					Address: "",
				},
				Storage: nil,
			},
			wantErr: true, // Will fail because config.yml doesn't exist
		},
		{
			name: "with environment variables",
			envVars: map[string]string{
				"FILE_STORAGE_PATH": testConfigPath,
			},
			want: &Config{
				FileStoragePath: testConfigPath,
				LogLevel:        -1, // Always set to -1 in NewConfig
				Server: Server{
					Address: "localhost:8080",
				},
				Storage: map[string]any{
					"type": "file",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment variables for the test
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			got, err := NewConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConfig() = %v, want %v", got, tt.want)
			}

			for k := range tt.envVars {
				os.Unsetenv(k)
			}
		})
	}
}
