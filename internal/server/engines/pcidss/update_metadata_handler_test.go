package pcidss

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
)

func TestBackend_UpdateMetadataHandler(t *testing.T) {
	ctrl := server.NewController(t)
	lg := server.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *server.BackendRouter
		repo     *Repository
		metadata *MetadataRepository
		lg       *logging.ZapLogger
	}
	type args struct {
		ctx    context.Context
		req    *server.LogicalRequest
		params *server.LogicalParams
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *server.LogicalResponse
		wantErr bool
		prepare func(mockStorage *server.MockILogicalStorage, b *Backend)
	}{
		{
			name: "successful metadata update",
			fields: fields{
				exist:    &atomic.Bool{},
				router:   &server.BackendRouter{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				lg:       lg,
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Params: map[string]string{
						"pan_token": "test-token",
					},
					Body: &MetadataBody{
						Metadata: map[string]string{
							"owner": "new-owner",
							"type":  "new-type",
						},
					},
				},
			},
			want: &server.LogicalResponse{
				Status: 200,
				Message: gin.H{
					"value": map[string]string{
						"owner": "new-owner",
						"type":  "new-type",
					},
				},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(server.Entry{
						Value: `{"owner":"old-owner","type":"old-type"}`,
					}, nil)
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "metadata not found",
			fields: fields{
				exist:    &atomic.Bool{},
				router:   &server.BackendRouter{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				lg:       lg,
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Params: map[string]string{
						"pan_token": "non-existent-token",
					},
					Body: &MetadataBody{
						Metadata: map[string]string{
							"owner": "new-owner",
						},
					},
				},
			},
			want: &server.LogicalResponse{
				Status: 404,
				Message: gin.H{
					"error": "metadata not found",
				},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Get(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, server.ErrEntryNotFound)
			},
		},
		{
			name: "storage error",
			fields: fields{
				exist:    &atomic.Bool{},
				router:   &server.BackendRouter{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				lg:       lg,
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Params: map[string]string{
						"pan_token": "test-token",
					},
					Body: &MetadataBody{
						Metadata: map[string]string{
							"owner": "new-owner",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/pci_dss/test-token/metadata").
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
				repo:     tt.fields.repo,
				metadata: NewMetadataRepository(mockStorage),
				lg:       tt.fields.lg,
			}
			tt.fields.exist.Store(true) // Set the atomic bool to true
			tt.prepare(mockStorage, b)

			got, err := b.UpdateMetadataHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.UpdateMetadataHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.UpdateMetadataHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
