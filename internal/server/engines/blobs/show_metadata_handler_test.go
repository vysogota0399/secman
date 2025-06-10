package blobs

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/server"
)

func TestBackend_showMetadataHandler(t *testing.T) {
	type args struct {
		ctx    context.Context
		req    *server.LogicalRequest
		params *server.LogicalParams
	}
	tests := []struct {
		name    string
		args    args
		want    *server.LogicalResponse
		wantErr bool
		setup   func(*Backend, *server.LogicalRequest, *server.MockBarrierStorage, *server.MockILogicalStorage)
	}{
		{
			name: "successfully shows metadata",
			args: args{
				ctx: context.Background(),
				params: &server.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
				},
			},
			want: &server.LogicalResponse{
				Status: http.StatusOK,
				Message: gin.H{
					"value": map[string]string{
						"file_name":  "test.txt",
						"created_at": "2024-01-01T00:00:00Z",
					},
				},
			},
			wantErr: false,
			setup: func(b *Backend, req *server.LogicalRequest, barrier *server.MockBarrierStorage, logicalStorage *server.MockILogicalStorage) {
				// Setup expectations for successful metadata retrieval
				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(server.Entry{Value: `{"file_name":"test.txt","created_at":"2024-01-01T00:00:00Z"}`}, nil)
			},
		},
		{
			name: "metadata not found",
			args: args{
				ctx: context.Background(),
				params: &server.LogicalParams{
					Params: map[string]string{
						"token": "non-existent-token",
					},
				},
			},
			want:    nil,
			wantErr: true,
			setup: func(b *Backend, req *server.LogicalRequest, barrier *server.MockBarrierStorage, logicalStorage *server.MockILogicalStorage) {
				// Setup expectations for non-existent metadata
				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/non-existent-token/metadata").
					Return(server.Entry{}, server.ErrEntryNotFound)
			},
		},
		{
			name: "invalid metadata format",
			args: args{
				ctx: context.Background(),
				params: &server.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
				},
			},
			want:    nil,
			wantErr: true,
			setup: func(b *Backend, req *server.LogicalRequest, barrier *server.MockBarrierStorage, logicalStorage *server.MockILogicalStorage) {
				// Setup expectations for invalid metadata format
				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(server.Entry{Value: `invalid json`}, nil)
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

			got, err := b.showMetadataHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.showMetadataHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Backend.showMetadataHandler() status = %v, want %v", got.Status, tt.want.Status)
				}
				if !reflect.DeepEqual(got.Message, tt.want.Message) {
					t.Errorf("Backend.showMetadataHandler() message = %v, want %v", got.Message, tt.want.Message)
				}
			}
		})
	}
}
