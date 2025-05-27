package pci_dss

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestBackend_ShowSecurityCodeHandler(t *testing.T) {
	ctrl := secman.NewController(t)
	defer ctrl.Finish()

	lg := secman.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *secman.BackendRouter
		metadata *MetadataRepository
	}
	type args struct {
		ctx    context.Context
		req    *secman.LogicalRequest
		params *secman.LogicalParams
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
			name: "successful retrieval",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"card_token":          "test_card_token",
						"security_code_token": "test_security_code_token",
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusOK,
				Message: gin.H{"security_code": "123"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{Value: "123"}, true, nil)
			},
		},
		{
			name: "security code not found",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"card_token":          "test_card_token",
						"security_code_token": "test_security_code_token",
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusNotFound,
				Message: gin.H{"error": "security code not found"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)
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
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Params: map[string]string{
						"card_token":          "test_card_token",
						"security_code_token": "test_security_code_token",
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, assert.AnError)
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

			got, err := b.ShowSecurityCodeHandler(tt.args.ctx, tt.args.req, tt.args.params)
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
