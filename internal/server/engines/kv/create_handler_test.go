package kv

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
)

func TestBackend_CreateHandler(t *testing.T) {
	ctrl := server.NewController(t)

	lg := server.NewLogger(t)

	type fields struct {
		exist  *atomic.Bool
		router *server.BackendRouter
		lg     *logging.ZapLogger
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
			name: "successful creation",
			fields: &fields{
				exist:  &atomic.Bool{},
				router: nil,
				lg:     lg,
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Body: &CreateSecretBody{
						Key:   "test-key",
						Value: "test-value",
					},
				},
			},
			want: &server.LogicalResponse{
				Status:  200,
				Message: gin.H{},
			},
			wantErr: false,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, false, nil)

				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "invalid body type",
			fields: &fields{
				exist:  &atomic.Bool{},
				router: nil,
				lg:     lg,
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Body: "invalid-body",
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				// No expectations needed as the error occurs before storage interaction
			},
		},
		{
			name: "storage error",
			fields: &fields{
				exist:  &atomic.Bool{},
				router: nil,
				lg:     lg,
			},
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{},
				params: &server.LogicalParams{
					Body: &CreateSecretBody{
						Key:   "test-key",
						Value: "test-value",
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *server.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(server.Entry{}, false, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := server.NewMockILogicalStorage(ctrl)
			b := &Backend{
				beMtx:    sync.RWMutex{},
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     NewRepository(mockStorage, lg),
				metadata: NewMetadataRepository(mockStorage),
				lg:       tt.fields.lg,
			}
			tt.prepare(mockStorage, b)

			got, err := b.CreateHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
