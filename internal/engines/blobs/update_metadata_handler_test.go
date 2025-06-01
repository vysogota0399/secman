package blobs

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestBackend_updateMetadataHandler(t *testing.T) {
	type args struct {
		ctx    context.Context
		req    *secman.LogicalRequest
		params *secman.LogicalParams
	}
	tests := []struct {
		name    string
		args    args
		want    *secman.LogicalResponse
		wantErr bool
		setup   func(*Backend, *secman.LogicalRequest, *secman.MockBarrierStorage, *secman.MockILogicalStorage)
	}{
		{
			name: "successfully updates metadata",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
					Body: &MetadataBody{
						Metadata: map[string]string{
							"new_key": "new_value",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status: http.StatusOK,
				Message: map[string]string{
					"existing_key": "existing_value",
					"new_key":      "new_value",
				},
			},
			wantErr: false,
			setup: func(b *Backend, req *secman.LogicalRequest, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				// Initialize HTTP request
				httpReq, _ := http.NewRequest("PUT", "/secrets/blobs/test-token/metadata", nil)
				req.Context.Request = httpReq

				// Setup expectations for successful metadata update
				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(secman.Entry{Value: `{"existing_key":"existing_value"}`}, nil)

				barrier.EXPECT().
					Update(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata", gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "metadata not found",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"token": "non-existent-token",
					},
					Body: &MetadataBody{
						Metadata: map[string]string{
							"new_key": "new_value",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status: http.StatusNotFound,
				Message: gin.H{
					"error": "metadata not found",
				},
			},
			wantErr: false,
			setup: func(b *Backend, req *secman.LogicalRequest, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				// Initialize HTTP request
				httpReq, _ := http.NewRequest("PUT", "/secrets/blobs/non-existent-token/metadata", nil)
				req.Context.Request = httpReq

				// Setup expectations for non-existent metadata
				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/non-existent-token/metadata").
					Return(secman.Entry{}, secman.ErrEntryNotFound)
			},
		},
		{
			name: "invalid body type",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
					Body: "invalid body type",
				},
			},
			want:    nil,
			wantErr: true,
			setup: func(b *Backend, req *secman.LogicalRequest, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				// Initialize HTTP request
				httpReq, _ := http.NewRequest("PUT", "/secrets/blobs/test-token/metadata", nil)
				req.Context.Request = httpReq
			},
		},
		{
			name: "update error",
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
					Body: &MetadataBody{
						Metadata: map[string]string{
							"new_key": "new_value",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			setup: func(b *Backend, req *secman.LogicalRequest, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				// Initialize HTTP request
				httpReq, _ := http.NewRequest("PUT", "/secrets/blobs/test-token/metadata", nil)
				req.Context.Request = httpReq

				// Setup expectations for successful get but failed update
				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(secman.Entry{Value: `{"existing_key":"existing_value"}`}, nil)

				barrier.EXPECT().
					Update(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata", gomock.Any(), gomock.Any()).
					Return(secman.ErrEntryNotFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			b, barrier, logicalStorage := NewTestBackend(t)

			if tt.setup != nil {
				tt.setup(b, tt.args.req, barrier, logicalStorage)
			}

			got, err := b.updateMetadataHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.updateMetadataHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Backend.updateMetadataHandler() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Message, tt.want.Message) {
					t.Errorf("Backend.updateMetadataHandler() message = %v, want %v", got.Message, tt.want.Message)
				}
			}
		})
	}
}
