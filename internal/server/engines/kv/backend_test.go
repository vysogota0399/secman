package kv

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
)

func TestNewBackend(t *testing.T) {
	type args struct {
		lg       *logging.ZapLogger
		repo     *Repository
		metadata *MetadataRepository
	}
	tests := []struct {
		name string
		args args
		want *Backend
	}{
		{
			name: "successful initialization",
			args: args{
				lg:       &logging.ZapLogger{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
			},
			want: &Backend{
				lg:       &logging.ZapLogger{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				exist:    &atomic.Bool{},
				beMtx:    sync.RWMutex{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBackend(tt.args.lg, tt.args.repo, tt.args.metadata)

			// Check that the basic fields are set correctly
			if got.lg != tt.args.lg {
				t.Errorf("NewBackend().lg = %v, want %v", got.lg, tt.args.lg)
			}
			if got.repo != tt.args.repo {
				t.Errorf("NewBackend().repo = %v, want %v", got.repo, tt.args.repo)
			}
			if got.metadata != tt.args.metadata {
				t.Errorf("NewBackend().metadata = %v, want %v", got.metadata, tt.args.metadata)
			}

			// Check that exist is initialized as false
			if got.exist.Load() {
				t.Error("NewBackend().exist should be initialized as false")
			}

			// Check that router is nil initially
			if got.router != nil {
				t.Error("NewBackend().router should be nil initially")
			}
		})
	}
}

func TestBackend_Paths(t *testing.T) {
	type fields struct {
		exist    *atomic.Bool
		router   *server.BackendRouter
		repo     *Repository
		metadata *MetadataRepository
		lg       *logging.ZapLogger
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]map[string]*server.Path
	}{
		{
			name: "check all handlers are initialized",
			fields: fields{
				exist:    &atomic.Bool{},
				router:   nil,
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				lg:       &logging.ZapLogger{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     tt.fields.repo,
				metadata: tt.fields.metadata,
				lg:       tt.fields.lg,
			}
			paths := b.Paths()

			// Check GET handlers
			if paths[http.MethodGet] == nil {
				t.Error("GET paths map is nil")
			}
			if paths[http.MethodGet][PATH+"/:key"].Handler == nil {
				t.Error("ShowHandler is nil")
			}
			if paths[http.MethodGet][PATH+"/:key/metadata"].Handler == nil {
				t.Error("ShowMetadataHandler is nil")
			}
			if paths[http.MethodGet][PATH].Handler == nil {
				t.Error("IndexHandler is nil")
			}

			// Check POST handler
			if paths[http.MethodPost] == nil {
				t.Error("POST paths map is nil")
			}
			if paths[http.MethodPost][PATH].Handler == nil {
				t.Error("CreateHandler is nil")
			}

			// Check DELETE handler
			if paths[http.MethodDelete] == nil {
				t.Error("DELETE paths map is nil")
			}
			if paths[http.MethodDelete][PATH+"/:key"].Handler == nil {
				t.Error("DeleteHandler is nil")
			}

			// Check PUT handler
			if paths[http.MethodPut] == nil {
				t.Error("PUT paths map is nil")
			}
			if paths[http.MethodPut][PATH+"/:key/metadata"].Handler == nil {
				t.Error("UpdateMetadataHandler is nil")
			}

			// Check that all paths have descriptions
			for method, methodPaths := range paths {
				for path, pathInfo := range methodPaths {
					if pathInfo.Description == "" {
						t.Errorf("Path %s %s has no description", method, path)
					}
				}
			}

			// Check fields for paths that require them
			checkFields := func(path string, fields []server.Field, expectedName string) {
				if len(fields) != 1 {
					t.Errorf("Path %s should have exactly 1 field, got %d", path, len(fields))
					return
				}
				if fields[0].Name != expectedName {
					t.Errorf("Path %s field name should be %s, got %s", path, expectedName, fields[0].Name)
				}
				if fields[0].Description == "" {
					t.Errorf("Path %s field description is empty", path)
				}
			}

			// Check fields for GET /:key
			checkFields(PATH+"/:key", paths[http.MethodGet][PATH+"/:key"].Fields, "key")

			// Check fields for GET /:key/metadata
			checkFields(PATH+"/:key/metadata", paths[http.MethodGet][PATH+"/:key/metadata"].Fields, "key")

			// Check fields for DELETE /:key
			checkFields(PATH+"/:key", paths[http.MethodDelete][PATH+"/:key"].Fields, "key")

			// Check fields for PUT /:key/metadata
			checkFields(PATH+"/:key/metadata", paths[http.MethodPut][PATH+"/:key/metadata"].Fields, "key")

			// Check that POST / has a body function
			if paths[http.MethodPost][PATH].Body == nil {
				t.Error("POST / path should have a body function")
			}

			// Check that PUT /:key/metadata has a body function
			if paths[http.MethodPut][PATH+"/:key/metadata"].Body == nil {
				t.Error("PUT /:key/metadata path should have a body function")
			}
		})
	}
}

func TestBackend_Enable(t *testing.T) {
	ctrl := server.NewController(t)
	defer ctrl.Finish()

	lg := server.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *server.BackendRouter
		metadata *MetadataRepository
	}
	type args struct {
		ctx context.Context
		req *server.LogicalRequest
	}
	tests := []struct {
		name    string
		fields  *fields
		args    args
		want    *server.LogicalResponse
		wantErr bool
		prepare func(mockStorage *server.MockILogicalStorage, b *Backend)
	}{
		{
			name: "successful enable",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
			},
			want: &server.LogicalResponse{
				Status:  http.StatusOK,
				Message: gin.H{"message": "kv enabled"},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "already enabled",
			fields: &fields{
				exist:    func() *atomic.Bool { b := &atomic.Bool{}; b.Store(true); return b }(),
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
			},
			want: &server.LogicalResponse{
				Status:  http.StatusNotModified,
				Message: gin.H{"message": "kv: already enabled"},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				b.exist.Store(true)
			},
		},
		{
			name: "enable error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := server.NewMockILogicalStorage(ctrl)
			b := &Backend{
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     NewRepository(mockStorage, lg),
				metadata: tt.fields.metadata,
				lg:       lg,
			}
			tt.prepare(mockStorage, b)

			got, err := b.Enable(tt.args.ctx, tt.args.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestBackend_PostUnseal(t *testing.T) {
	ctrl := server.NewController(t)

	lg := server.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *server.BackendRouter
		metadata *MetadataRepository
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  *fields
		args    args
		wantErr bool
		prepare func(mockStorage *server.MockILogicalStorage, b *Backend)
	}{
		{
			name: "successful post unseal",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, true, nil)
			},
		},
		{
			name: "engine not enabled",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, false, nil)
			},
		},
		{
			name: "storage error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, false, server.ErrEntryNotFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := server.NewMockILogicalStorage(ctrl)
			b := &Backend{
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     NewRepository(mockStorage, lg),
				metadata: tt.fields.metadata,
				lg:       lg,
			}
			tt.prepare(mockStorage, b)

			err := b.PostUnseal(tt.args.ctx)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.True(t, b.exist.Load(), "exist flag should be set to true after successful post unseal")
			}
		})
	}
}
