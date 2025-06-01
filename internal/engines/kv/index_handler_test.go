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
	"github.com/vysogota0399/secman/internal/secman"
)

func TestBackend_IndexHandler(t *testing.T) {
	ctrl := secman.NewController(t)

	lg := secman.NewLogger(t)

	type fields struct {
		exist  *atomic.Bool
		router *secman.BackendRouter
		lg     *logging.ZapLogger
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
			name: "successful listing",
			fields: &fields{
				exist:  &atomic.Bool{},
				router: nil,
				lg:     lg,
			},
			args: args{
				ctx:    context.Background(),
				req:    &secman.LogicalRequest{},
				params: &secman.LogicalParams{},
			},
			want: &secman.LogicalResponse{
				Status: 200,
				Message: gin.H{
					"entries": []secman.Entry{
						{
							Path:  "secrets/kv/key1",
							Key:   "/key1",
							Value: "value1",
						},
						{
							Path:  "secrets/kv/key2",
							Key:   "/key2",
							Value: "value2",
						},
					},
				},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					List(gomock.Any(), gomock.Any()).
					Return([]secman.Entry{
						{
							Path:  "secrets/kv/key1",
							Value: "value1",
						},
						{
							Path:  "secrets/kv/key2",
							Value: "value2",
						},
					}, nil)
			},
		},
		{
			name: "empty listing",
			fields: &fields{
				exist:  &atomic.Bool{},
				router: nil,
				lg:     lg,
			},
			args: args{
				ctx:    context.Background(),
				req:    &secman.LogicalRequest{},
				params: &secman.LogicalParams{},
			},
			want: &secman.LogicalResponse{
				Status: 200,
				Message: gin.H{
					"entries": []secman.Entry{},
				},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					List(gomock.Any(), gomock.Any()).
					Return([]secman.Entry{}, nil)
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
				ctx:    context.Background(),
				req:    &secman.LogicalRequest{},
				params: &secman.LogicalParams{},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					List(gomock.Any(), gomock.Any()).
					Return(nil, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := secman.NewMockILogicalStorage(ctrl)
			b := &Backend{
				beMtx:    sync.RWMutex{},
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     NewRepository(mockStorage, lg),
				metadata: NewMetadataRepository(mockStorage),
				lg:       tt.fields.lg,
			}
			tt.prepare(mockStorage, b)

			got, err := b.IndexHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
