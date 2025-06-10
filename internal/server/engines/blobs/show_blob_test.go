package blobs

import (
	"context"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/server"
)

func TestBackend_showBlob(t *testing.T) {
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
			name: "successfully shows blob",
			args: args{
				ctx: context.Background(),
				params: &server.LogicalParams{
					Params: map[string]string{
						"token": "test-token",
					},
				},
			},
			want: &server.LogicalResponse{
				Status: 200,
				Message: gin.H{
					"blob": &Blob{
						Key:   "test-blob-key",
						Value: &mockReadCloser{content: "test-content"},
						Size:  12,
					},
				},
				Headers: map[string]string{
					"Content-Type":        "application/octet-stream",
					"Content-Disposition": "attachment; filename=test.txt",
					"Content-Length":      "12",
				},
				Reader:      &mockReadCloser{content: "test-content"},
				ContentSize: 12,
			},
			wantErr: false,
			setup: func(b *Backend, req *server.LogicalRequest, barrier *server.MockBarrierStorage, logicalStorage *server.MockILogicalStorage) {
				// Setup expectations for successful blob retrieval
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "test-token").
					Return(server.Entry{Value: "test-blob-key"}, true, nil)

				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(server.Entry{Value: `{"file_name":"test.txt"}`}, nil)

				b.s3.(*MockS3).EXPECT().
					Get(gomock.Any(), "test-blob-key").
					Return(&Blob{
						Key:   "test-blob-key",
						Value: &mockReadCloser{content: "test-content"},
						Size:  12,
					}, nil)
			},
		},
		{
			name: "blob not found",
			args: args{
				ctx: context.Background(),
				params: &server.LogicalParams{
					Params: map[string]string{
						"token": "non-existent-token",
					},
				},
			},
			want: &server.LogicalResponse{
				Status: 404,
				Message: gin.H{
					"error": "blob not found",
				},
			},
			wantErr: false,
			setup: func(b *Backend, req *server.LogicalRequest, barrier *server.MockBarrierStorage, logicalStorage *server.MockILogicalStorage) {
				// Setup expectations for non-existent blob
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "non-existent-token").
					Return(server.Entry{}, false, nil)
			},
		},
		{
			name: "metadata not found",
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
				// Setup expectations for blob found but metadata missing
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "test-token").
					Return(server.Entry{Value: "test-blob-key"}, true, nil)

				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(server.Entry{}, server.ErrEntryNotFound)
			},
		},
		{
			name: "empty file name in metadata",
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
				// Setup expectations for blob found but metadata has empty file name
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "test-token").
					Return(server.Entry{Value: "test-blob-key"}, true, nil)

				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(server.Entry{Value: `{"file_name":""}`}, nil)
			},
		},
		{
			name: "s3 get error",
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
				// Setup expectations for blob found but S3 get fails
				logicalStorage.EXPECT().
					GetOk(gomock.Any(), "test-token").
					Return(server.Entry{Value: "test-blob-key"}, true, nil)

				barrier.EXPECT().
					Get(gomock.Any(), "unsealed/secrets/blobs/test-token/metadata").
					Return(server.Entry{Value: `{"file_name":"test.txt"}`}, nil)

				b.s3.(*MockS3).EXPECT().
					Get(gomock.Any(), "test-blob-key").
					Return(nil, server.ErrEntryNotFound)
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

			got, err := b.showBlob(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.showBlob() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Backend.showBlob() status = %v, want %v", got.Status, tt.want.Status)
				}
				if tt.want.Message != nil && got.Message != nil {
					wantMsg := tt.want.Message.(gin.H)
					gotMsg := got.Message.(gin.H)
					if wantMsg["error"] != nil && gotMsg["error"] != wantMsg["error"] {
						t.Errorf("Backend.showBlob() message = %v, want %v", got.Message, tt.want.Message)
					}
					if wantMsg["blob"] != nil {
						wantBlob := wantMsg["blob"].(*Blob)
						gotBlob := gotMsg["blob"].(*Blob)
						if wantBlob.Key != gotBlob.Key {
							t.Errorf("Backend.showBlob() blob key = %v, want %v", gotBlob.Key, wantBlob.Key)
						}
						if wantBlob.Size != gotBlob.Size {
							t.Errorf("Backend.showBlob() blob size = %v, want %v", gotBlob.Size, wantBlob.Size)
						}
					}
				}
				if tt.want.Headers != nil {
					for k, v := range tt.want.Headers {
						if got.Headers[k] != v {
							t.Errorf("Backend.showBlob() header %s = %v, want %v", k, got.Headers[k], v)
						}
					}
				}
				if tt.want.ContentSize != got.ContentSize {
					t.Errorf("Backend.showBlob() content size = %v, want %v", got.ContentSize, tt.want.ContentSize)
				}
			}
		})
	}
}

// mockReadCloser is a simple implementation of io.ReadCloser for testing
type mockReadCloser struct {
	content string
	pos     int
}

func (m *mockReadCloser) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.content) {
		return 0, nil
	}
	n = copy(p, m.content[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockReadCloser) Close() error {
	return nil
}
