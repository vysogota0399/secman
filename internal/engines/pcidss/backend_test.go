package pcidss

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
	"github.com/vysogota0399/secman/internal/secman"
)

func TestBackend_PostUnseal(t *testing.T) {
	type fields struct {
		exist    *atomic.Bool
		router   *secman.BackendRouter
		repo     *Repository
		metadata *MetadataRepository
		lg       *logging.ZapLogger
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
		// TODO: Add test cases.
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
			if err := b.PostUnseal(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Backend.PostUnseal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBackend_Enable(t *testing.T) {
	ctrl := secman.NewController(t)
	defer ctrl.Finish()

	lg := secman.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *secman.BackendRouter
		metadata *MetadataRepository
	}
	type args struct {
		ctx context.Context
		req *secman.LogicalRequest
	}
	tests := []struct {
		name    string
		fields  *fields
		args    args
		want    *secman.LogicalResponse
		wantErr bool
		prepare func(mockStorage *secman.MockILogicalStorage, b *Backend)
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
				req: &secman.LogicalRequest{},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusOK,
				Message: gin.H{"message": "pci_dss enabled"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
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
				req: &secman.LogicalRequest{},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusNotModified,
				Message: gin.H{"message": "pci_dss: already enabled"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
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
				req: &secman.LogicalRequest{},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := secman.NewMockILogicalStorage(ctrl)
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
