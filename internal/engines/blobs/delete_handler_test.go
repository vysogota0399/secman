package blobs

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestBackend_deleteHandler(t *testing.T) {
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
			name: "successful deletion",
			args: args{
				ctx: context.Background(),
				params: &secman.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
				},
			},
			want: &secman.LogicalResponse{
				Status: 200,
			},
			wantErr: false,
			setup: func(b *Backend, req *secman.LogicalRequest, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				// Setup expectations for successful deletion
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "test-token").
					Return(secman.Entry{Value: "test-blob-key"}, true, nil)
				logicalStorage.EXPECT().
					Delete(gomock.Any(), "test-token").
					Return(nil)
				barrier.EXPECT().
					Delete(gomock.Any(), "secrets/blobs/test-token/metadata").
					Return(nil)
				b.s3.(*MockS3).EXPECT().
					Delete(gomock.Any(), "test-blob-key").
					Return(nil)
			},
		},
		{
			name: "blob not found",
			args: args{
				ctx: context.Background(),
				params: &secman.LogicalParams{
					Params: map[string]string{
						"token": "non-existent-token",
					},
				},
			},
			want: &secman.LogicalResponse{
				Status: 404,
				Message: gin.H{
					"error": "blob not found",
				},
			},
			wantErr: false,
			setup: func(b *Backend, req *secman.LogicalRequest, barrier *secman.MockBarrierStorage, logicalStorage *secman.MockILogicalStorage) {
				// Setup expectations for non-existent blob
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "non-existent-token").
					Return(secman.Entry{}, false, nil)
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

			got, err := b.deleteHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.deleteHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got.Status != tt.want.Status {
				t.Errorf("Backend.deleteHandler() status = %v, want %v", got.Status, tt.want.Status)
			}
			if tt.want.Message != nil && got.Message != nil {
				wantMsg := tt.want.Message.(gin.H)
				gotMsg := got.Message.(gin.H)
				if gotMsg["error"] != wantMsg["error"] {
					t.Errorf("Backend.deleteHandler() message = %v, want %v", got.Message, tt.want.Message)
				}
			}
		})
	}
}
