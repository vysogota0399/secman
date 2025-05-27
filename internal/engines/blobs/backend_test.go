package blobs

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestNewBackend(t *testing.T) {
	type args struct {
		lg           *logging.ZapLogger
		blobRepo     *Repository
		metadataRepo *MetadataRepository
	}
	tests := []struct {
		name string
		args args
		want *Backend
	}{
		{
			name: "creates new backend with correct fields",
			args: args{
				lg:           &logging.ZapLogger{},
				blobRepo:     &Repository{},
				metadataRepo: &MetadataRepository{},
			},
			want: &Backend{
				lg:       &logging.ZapLogger{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				exist:    &atomic.Bool{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBackend(tt.args.lg, tt.args.blobRepo, tt.args.metadataRepo, NewMockS3(gomock.NewController(t)))
			// Compare fields individually since exist is a pointer
			if got.lg != tt.args.lg {
				t.Errorf("NewBackend().lg = %v, want %v", got.lg, tt.args.lg)
			}
			if got.repo != tt.args.blobRepo {
				t.Errorf("NewBackend().repo = %v, want %v", got.repo, tt.args.blobRepo)
			}
			if got.metadata != tt.args.metadataRepo {
				t.Errorf("NewBackend().metadata = %v, want %v", got.metadata, tt.args.metadataRepo)
			}
			if got.exist == nil {
				t.Error("NewBackend().exist is nil")
			}
			if got.exist.Load() {
				t.Error("NewBackend().exist should be false")
			}
		})
	}
}

func TestBackend_Help(t *testing.T) {
	type fields struct {
		beMtx      sync.RWMutex
		exist      *atomic.Bool
		router     *secman.BackendRouter
		repo       *Repository
		metadata   *MetadataRepository
		lg         *logging.ZapLogger
		blobParams *BlobParams
		s3         S3
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "returns correct help message",
			fields: fields{
				beMtx:      sync.RWMutex{},
				exist:      &atomic.Bool{},
				router:     nil,
				repo:       nil,
				metadata:   nil,
				lg:         nil,
				blobParams: nil,
				s3:         nil,
			},
			want: "Blobs backend, uses key-value pairs to store data in S3-compatible storage",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:      tt.fields.beMtx,
				exist:      tt.fields.exist,
				router:     tt.fields.router,
				repo:       tt.fields.repo,
				metadata:   tt.fields.metadata,
				lg:         tt.fields.lg,
				blobParams: tt.fields.blobParams,
				s3:         tt.fields.s3,
			}
			if got := b.Help(); got != tt.want {
				t.Errorf("Backend.Help() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_SetRouter(t *testing.T) {
	type fields struct {
		beMtx      sync.RWMutex
		exist      *atomic.Bool
		router     *secman.BackendRouter
		repo       *Repository
		metadata   *MetadataRepository
		lg         *logging.ZapLogger
		blobParams *BlobParams
		s3         S3
	}
	type args struct {
		router *secman.BackendRouter
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "sets router correctly",
			fields: fields{
				beMtx:      sync.RWMutex{},
				exist:      &atomic.Bool{},
				router:     nil,
				repo:       nil,
				metadata:   nil,
				lg:         nil,
				blobParams: nil,
				s3:         nil,
			},
			args: args{
				router: &secman.BackendRouter{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:      tt.fields.beMtx,
				exist:      tt.fields.exist,
				router:     tt.fields.router,
				repo:       tt.fields.repo,
				metadata:   tt.fields.metadata,
				lg:         tt.fields.lg,
				blobParams: tt.fields.blobParams,
				s3:         tt.fields.s3,
			}
			b.SetRouter(tt.args.router)
			if b.router != tt.args.router {
				t.Errorf("Backend.SetRouter() router = %v, want %v", b.router, tt.args.router)
			}
		})
	}
}

func TestBackend_Router(t *testing.T) {
	type fields struct {
		beMtx      sync.RWMutex
		exist      *atomic.Bool
		router     *secman.BackendRouter
		repo       *Repository
		metadata   *MetadataRepository
		lg         *logging.ZapLogger
		blobParams *BlobParams
		s3         S3
	}
	tests := []struct {
		name   string
		fields fields
		want   *secman.BackendRouter
	}{
		{
			name: "returns router correctly",
			fields: fields{
				beMtx:      sync.RWMutex{},
				exist:      &atomic.Bool{},
				router:     &secman.BackendRouter{},
				repo:       nil,
				metadata:   nil,
				lg:         nil,
				blobParams: nil,
				s3:         nil,
			},
			want: &secman.BackendRouter{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:      tt.fields.beMtx,
				exist:      tt.fields.exist,
				router:     tt.fields.router,
				repo:       tt.fields.repo,
				metadata:   tt.fields.metadata,
				lg:         tt.fields.lg,
				blobParams: tt.fields.blobParams,
				s3:         tt.fields.s3,
			}
			if got := b.Router(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.Router() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_RootPath(t *testing.T) {
	type fields struct {
		beMtx      sync.RWMutex
		exist      *atomic.Bool
		router     *secman.BackendRouter
		repo       *Repository
		metadata   *MetadataRepository
		lg         *logging.ZapLogger
		blobParams *BlobParams
		s3         S3
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "returns correct root path",
			fields: fields{
				beMtx:      sync.RWMutex{},
				exist:      &atomic.Bool{},
				router:     nil,
				repo:       nil,
				metadata:   nil,
				lg:         nil,
				blobParams: nil,
				s3:         nil,
			},
			want: "/secrets/blobs",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:      tt.fields.beMtx,
				exist:      tt.fields.exist,
				router:     tt.fields.router,
				repo:       tt.fields.repo,
				metadata:   tt.fields.metadata,
				lg:         tt.fields.lg,
				blobParams: tt.fields.blobParams,
				s3:         tt.fields.s3,
			}
			if got := b.RootPath(); got != tt.want {
				t.Errorf("Backend.RootPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_rndToken(t *testing.T) {
	type fields struct {
		beMtx      sync.RWMutex
		exist      *atomic.Bool
		router     *secman.BackendRouter
		repo       *Repository
		metadata   *MetadataRepository
		lg         *logging.ZapLogger
		blobParams *BlobParams
		s3         S3
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "generates random token",
			fields: fields{
				beMtx:      sync.RWMutex{},
				exist:      &atomic.Bool{},
				router:     nil,
				repo:       nil,
				metadata:   nil,
				lg:         nil,
				blobParams: nil,
				s3:         nil,
			},
			want: "", // We can't predict the exact token, but we can verify its properties
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:      tt.fields.beMtx,
				exist:      tt.fields.exist,
				router:     tt.fields.router,
				repo:       tt.fields.repo,
				metadata:   tt.fields.metadata,
				lg:         tt.fields.lg,
				blobParams: tt.fields.blobParams,
				s3:         tt.fields.s3,
			}
			got := b.rndToken()
			// Verify token properties
			if len(got) == 0 {
				t.Error("Backend.rndToken() returned empty string")
			}
			if len(got) != 88 { // Base64 encoded 64 bytes = 88 characters
				t.Errorf("Backend.rndToken() length = %v, want %v", len(got), 88)
			}
			// Verify no forward slashes in the token
			for _, c := range got {
				if c == '/' {
					t.Error("Backend.rndToken() contains forward slash")
				}
			}
		})
	}
}

func TestBackend_Paths(t *testing.T) {
	type fields struct {
		beMtx      sync.RWMutex
		exist      *atomic.Bool
		router     *secman.BackendRouter
		repo       *Repository
		metadata   *MetadataRepository
		lg         *logging.ZapLogger
		blobParams *BlobParams
		s3         S3
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]map[string]*secman.Path
	}{
		{
			name: "returns correct paths configuration",
			fields: fields{
				beMtx:      sync.RWMutex{},
				exist:      &atomic.Bool{},
				router:     nil,
				repo:       nil,
				metadata:   nil,
				lg:         nil,
				blobParams: nil,
				s3:         nil,
			},
			want: map[string]map[string]*secman.Path{
				"GET": {
					"/secrets/blobs/:token": {
						Description: "Get a blob",
						Fields: []secman.Field{
							{
								Name:        "token",
								Description: "The token of the blob",
							},
						},
					},
					"/secrets/blobs/:token/metadata": {
						Description: "Get the metadata of a blob",
						Fields: []secman.Field{
							{
								Name:        "token",
								Description: "The token of the blob",
							},
						},
					},
				},
				"POST": {
					"/secrets/blobs": {
						Description: "Create a blob",
						Body:        func() any { return &MetadataBody{} },
					},
				},
				"DELETE": {
					"/secrets/blobs/:token": {
						Description: "Delete a blob",
						Fields: []secman.Field{
							{
								Name:        "token",
								Description: "The token of the blob",
							},
						},
					},
				},
				"PUT": {
					"/secrets/blobs/:token/metadata": {
						Description: "Update the metadata of a blob",
						Fields: []secman.Field{
							{
								Name:        "token",
								Description: "The token of the blob",
							},
						},
						Body: func() any { return &MetadataBody{} },
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:      tt.fields.beMtx,
				exist:      tt.fields.exist,
				router:     tt.fields.router,
				repo:       tt.fields.repo,
				metadata:   tt.fields.metadata,
				lg:         tt.fields.lg,
				blobParams: tt.fields.blobParams,
				s3:         tt.fields.s3,
			}
			got := b.Paths()

			// Compare HTTP methods
			if len(got) != len(tt.want) {
				t.Errorf("Backend.Paths() number of methods = %v, want %v", len(got), len(tt.want))
			}

			// Compare each method's paths
			for method, paths := range tt.want {
				gotPaths, exists := got[method]
				if !exists {
					t.Errorf("Backend.Paths() missing method %v", method)
					continue
				}

				if len(gotPaths) != len(paths) {
					t.Errorf("Backend.Paths()[%v] number of paths = %v, want %v", method, len(gotPaths), len(paths))
					continue
				}

				// Compare each path's configuration
				for path, wantPath := range paths {
					gotPath, exists := gotPaths[path]
					if !exists {
						t.Errorf("Backend.Paths()[%v] missing path %v", method, path)
						continue
					}

					// Verify handler is not nil
					if gotPath.Handler == nil {
						t.Errorf("Backend.Paths()[%v][%v].Handler is nil", method, path)
					}

					// Compare description
					if gotPath.Description != wantPath.Description {
						t.Errorf("Backend.Paths()[%v][%v].Description = %v, want %v", method, path, gotPath.Description, wantPath.Description)
					}

					// Compare fields
					if len(gotPath.Fields) != len(wantPath.Fields) {
						t.Errorf("Backend.Paths()[%v][%v].Fields length = %v, want %v", method, path, len(gotPath.Fields), len(wantPath.Fields))
					} else {
						for i, wantField := range wantPath.Fields {
							gotField := gotPath.Fields[i]
							if gotField.Name != wantField.Name {
								t.Errorf("Backend.Paths()[%v][%v].Fields[%v].Name = %v, want %v", method, path, i, gotField.Name, wantField.Name)
							}
							if gotField.Description != wantField.Description {
								t.Errorf("Backend.Paths()[%v][%v].Fields[%v].Description = %v, want %v", method, path, i, gotField.Description, wantField.Description)
							}
						}
					}

					// Compare body function if present
					if (gotPath.Body == nil) != (wantPath.Body == nil) {
						t.Errorf("Backend.Paths()[%v][%v].Body presence = %v, want %v", method, path, gotPath.Body != nil, wantPath.Body != nil)
					}
				}
			}
		})
	}
}

func TestBackend_Enable(t *testing.T) {
	type args struct {
		ctx context.Context
		req *secman.LogicalRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *secman.LogicalResponse
		wantErr bool
		setup   func(*Backend, *secman.MockBarrierStorage, *secman.MockILogicalStorage)
	}{
		{
			name: "successfully enables backend",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{
								"adapter": {
									"url": "http://localhost:9000",
									"user": "minioadmin",
									"password": "minioadmin",
									"ssl": false,
									"bucket": "test-bucket"
								}
							}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusOK,
				Message: "blobs enabled",
			},
			wantErr: false,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				b.exist.Store(false)
				logicalStorage.EXPECT().
					Update(gomock.Any(), "", gomock.Any(), gomock.Any()).
					Return(nil)

				logicalStorage.EXPECT().
					Prefix().
					Return("secrets/blobs")

				s3 := b.s3.(*MockS3)
				s3.EXPECT().
					Start(b).
					Return(nil)
			},
		},
		{
			name: "returns error when already enabled",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{
								"adapter": {
									"url": "http://localhost:9000",
									"user": "minioadmin",
									"password": "minioadmin",
									"ssl": false,
									"bucket": "test-bucket"
								}
							}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusNotModified,
				Message: "blobs: already enabled",
			},
			wantErr: false,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				b.exist.Store(true)
			},
		},
		{
			name: "returns error when missing required fields",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{
								"adapter": {
									"url": "",
									"user": "",
									"password": "",
									"ssl": false,
									"bucket": ""
								}
							}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: "invalid request, missing required field: url",
			},
			wantErr: false,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				b.exist.Store(false)
			},
		},
		{
			name: "returns error when adapter has invalid attributes",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{
								"adapter": {
									"url": "invalid-url",
									"user": "minioadmin",
									"password": "minioadmin",
									"ssl": "not-a-boolean",
									"bucket": "test-bucket"
								}
							}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: "invalid request",
			},
			wantErr: false,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				b.exist.Store(false)
			},
		},
		{
			name: "returns error when adapter has invalid credentials",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{
						Request: &http.Request{
							Header: http.Header{
								"Content-Type": []string{"application/json"},
							},
							Body: io.NopCloser(strings.NewReader(`{
								"adapter": {
									"url": "http://localhost:9000",
									"user": "",
									"password": "",
									"ssl": false,
									"bucket": "test-bucket"
								}
							}`)),
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: "invalid request, missing required field: user",
			},
			wantErr: false,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				b.exist.Store(false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, barrier, logicalStorage := NewTestBackend(t)
			if tt.setup != nil {
				tt.setup(b, barrier, logicalStorage)
			}
			got, err := b.Enable(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.Enable() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.Enable() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBackend_PostUnseal(t *testing.T) {
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		setup   func(*Backend, *secman.MockBarrierStorage, *secman.MockILogicalStorage)
	}{
		{
			name: "successful post unseal",
			args: args{
				ctx: context.Background(),
			},
			wantErr: false,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{
						Key:   "config",
						Value: `{"adapter":{"url":"http://localhost:9000","user":"minioadmin","password":"minioadmin","ssl":false,"bucket":"test-bucket"}}`,
					}, true, nil)

				s3 := b.s3.(*MockS3)
				s3.EXPECT().
					Start(b).
					Return(nil)
			},
		},
		{
			name: "engine not enabled",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)
			},
		},
		{
			name: "storage error",
			args: args{
				ctx: context.Background(),
			},
			wantErr: true,
			setup: func(b *Backend, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, secman.ErrEntryNotFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, barrier, logicalStorage := NewTestBackend(t)
			if tt.setup != nil {
				tt.setup(b, barrier, logicalStorage)
			}
			err := b.PostUnseal(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.PostUnseal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !b.exist.Load() {
				t.Error("Backend.PostUnseal() exist flag should be set to true after successful post unseal")
			}
		})
	}
}
