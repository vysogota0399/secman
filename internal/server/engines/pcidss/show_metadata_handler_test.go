package pcidss

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/server"
)

func TestBackend_ShowMetadataHandler(t *testing.T) {
	ctrl := server.NewController(t)
	defer ctrl.Finish()

	lg := server.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *server.BackendRouter
		metadata *MetadataRepository
	}
	type args struct {
		ctx    context.Context
		req    *server.LogicalRequest
		params *server.LogicalParams
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
			name: "successful metadata retrieval",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Params: map[string]string{
						"pan_token": "test_pan_token",
					},
				},
			},
			want: &server.LogicalResponse{
				Status: http.StatusOK,
				Message: gin.H{
					"value": map[string]string{
						"created_at": "2024-03-20T12:00:00Z",
					},
				},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)
				mockStorage.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(server.Entry{
						Value: `{"created_at":"2024-03-20T12:00:00Z"}`,
					}, nil)
			},
		},
		{
			name: "metadata not found",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Params: map[string]string{
						"pan_token": "test_pan_token",
					},
				},
			},
			want: &server.LogicalResponse{
				Status:  http.StatusNotFound,
				Message: gin.H{"error": "metadata not found"},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)
				mockStorage.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, server.ErrEntryNotFound)
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
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Params: map[string]string{
						"pan_token": "test_pan_token",
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)
				mockStorage.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, assert.AnError)
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

			got, err := b.ShowMetadataHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want.Status, got.Status)
				assert.Equal(t, tt.want.Message, got.Message)
			}
		})
	}
}
