package secman

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/logging"
)

func TestNewCoreRepository(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := NewMockBarrierStorage(ctrl)
	mockLogger := &logging.ZapLogger{}

	repo := NewCoreRepository(mockStorage, mockLogger)

	if repo.storage != mockStorage {
		t.Errorf("NewCoreRepository() storage = %v, want %v", repo.storage, mockStorage)
	}
	if repo.log != mockLogger {
		t.Errorf("NewCoreRepository() log = %v, want %v", repo.log, mockLogger)
	}
}

func TestCoreRepository_IsCoreInitialized(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := NewMockBarrierStorage(ctrl)
	mockLogger := &logging.ZapLogger{}
	repo := NewCoreRepository(mockStorage, mockLogger)

	tests := []struct {
		name       string
		setupMocks func()
		want       bool
		wantErr    bool
	}{
		{
			name: "success - initialized",
			setupMocks: func() {
				coreEntry := CoreEntry{Initialized: true}
				value, _ := json.Marshal(coreEntry)
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{Value: string(value)}, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "success - not initialized",
			setupMocks: func() {
				coreEntry := CoreEntry{Initialized: false}
				value, _ := json.Marshal(coreEntry)
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{Value: string(value)}, nil)
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "success - entry not found",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{}, ErrEntryNotFound)
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "error - storage error",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{}, errors.New("storage error"))
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			got, err := repo.IsCoreInitialized(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("CoreRepository.IsCoreInitialized() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CoreRepository.IsCoreInitialized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCoreRepository_SetCoreInitialized(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := NewMockBarrierStorage(ctrl)
	mockLogger := &logging.ZapLogger{}
	repo := NewCoreRepository(mockStorage, mockLogger)

	tests := []struct {
		name        string
		initialized bool
		setupMocks  func()
		wantErr     bool
	}{
		{
			name:        "success - set initialized",
			initialized: true,
			setupMocks: func() {
				coreEntry := CoreEntry{Initialized: false}
				value, _ := json.Marshal(coreEntry)
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{Value: string(value)}, nil)

				newCoreEntry := CoreEntry{Initialized: true}
				newValue, _ := json.Marshal(newCoreEntry)
				mockStorage.EXPECT().
					Update(gomock.Any(), coreParamsPath, Entry{Value: string(newValue)}, gomock.Any()).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "success - set not initialized",
			initialized: false,
			setupMocks: func() {
				coreEntry := CoreEntry{Initialized: true}
				value, _ := json.Marshal(coreEntry)
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{Value: string(value)}, nil)

				newCoreEntry := CoreEntry{Initialized: false}
				newValue, _ := json.Marshal(newCoreEntry)
				mockStorage.EXPECT().
					Update(gomock.Any(), coreParamsPath, Entry{Value: string(newValue)}, gomock.Any()).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "success - entry not found",
			initialized: true,
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{}, ErrEntryNotFound)

				newCoreEntry := CoreEntry{Initialized: true}
				newValue, _ := json.Marshal(newCoreEntry)
				mockStorage.EXPECT().
					Update(gomock.Any(), coreParamsPath, Entry{Value: string(newValue)}, gomock.Any()).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "error - storage error on get",
			initialized: true,
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{}, errors.New("storage error"))
			},
			wantErr: true,
		},
		{
			name:        "error - storage error on update",
			initialized: true,
			setupMocks: func() {
				coreEntry := CoreEntry{Initialized: false}
				value, _ := json.Marshal(coreEntry)
				mockStorage.EXPECT().
					Get(gomock.Any(), coreParamsPath).
					Return(Entry{Value: string(value)}, nil)

				newCoreEntry := CoreEntry{Initialized: true}
				newValue, _ := json.Marshal(newCoreEntry)
				mockStorage.EXPECT().
					Update(gomock.Any(), coreParamsPath, Entry{Value: string(newValue)}, gomock.Any()).
					Return(errors.New("storage error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			if err := repo.SetCoreInitialized(context.Background(), tt.initialized); (err != nil) != tt.wantErr {
				t.Errorf("CoreRepository.SetCoreInitialized() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCoreRepository_IsEngineExist(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := NewMockBarrierStorage(ctrl)
	mockLogger := &logging.ZapLogger{}
	repo := NewCoreRepository(mockStorage, mockLogger)

	tests := []struct {
		name       string
		searchPath string
		setupMocks func()
		want       bool
		wantErr    bool
	}{
		{
			name:       "success - engine exists",
			searchPath: "test/path",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(Entry{Value: "test"}, nil)
			},
			want:    true,
			wantErr: false,
		},
		{
			name:       "success - engine does not exist",
			searchPath: "test/path",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(Entry{}, ErrEntryNotFound)
			},
			want:    false,
			wantErr: false,
		},
		{
			name:       "error - storage error",
			searchPath: "test/path",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(Entry{}, errors.New("storage error"))
			},
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			got, err := repo.IsEngineExist(context.Background(), tt.searchPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoreRepository.IsEngineExist() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CoreRepository.IsEngineExist() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCoreRepository_GetCoreAuthConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := NewMockBarrierStorage(ctrl)
	mockLogger := &logging.ZapLogger{}
	repo := NewCoreRepository(mockStorage, mockLogger)

	tests := []struct {
		name       string
		setupMocks func()
		want       *Auth
		wantErr    bool
	}{
		{
			name: "success - get auth config",
			setupMocks: func() {
				auth := &Auth{Engines: []authPath{"test/path"}}
				value, _ := json.Marshal(auth)
				mockStorage.EXPECT().
					Get(gomock.Any(), coreAuthPath).
					Return(Entry{Value: string(value)}, nil)
			},
			want:    &Auth{Engines: []authPath{"test/path"}},
			wantErr: false,
		},
		{
			name: "error - entry not found",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreAuthPath).
					Return(Entry{}, ErrEntryNotFound)
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error - storage error",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreAuthPath).
					Return(Entry{}, errors.New("storage error"))
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "error - invalid json",
			setupMocks: func() {
				mockStorage.EXPECT().
					Get(gomock.Any(), coreAuthPath).
					Return(Entry{Value: "invalid json"}, nil)
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			got, err := repo.GetCoreAuthConfig(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("CoreRepository.GetCoreAuthConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CoreRepository.GetCoreAuthConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCoreRepository_UpdateCoreAuthConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockStorage := NewMockBarrierStorage(ctrl)
	mockLogger := &logging.ZapLogger{}
	repo := NewCoreRepository(mockStorage, mockLogger)

	tests := []struct {
		name       string
		authConfig *Auth
		setupMocks func()
		wantErr    bool
	}{
		{
			name:       "success - update auth config",
			authConfig: &Auth{Engines: []authPath{"test/path"}},
			setupMocks: func() {
				value, _ := json.Marshal(&Auth{Engines: []authPath{"test/path"}})
				mockStorage.EXPECT().
					Update(gomock.Any(), coreAuthPath, Entry{Value: string(value)}, gomock.Any()).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:       "error - storage error",
			authConfig: &Auth{Engines: []authPath{"test/path"}},
			setupMocks: func() {
				value, _ := json.Marshal(&Auth{Engines: []authPath{"test/path"}})
				mockStorage.EXPECT().
					Update(gomock.Any(), coreAuthPath, Entry{Value: string(value)}, gomock.Any()).
					Return(errors.New("storage error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			if err := repo.UpdateCoreAuthConfig(context.Background(), tt.authConfig); (err != nil) != tt.wantErr {
				t.Errorf("CoreRepository.UpdateCoreAuthConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
