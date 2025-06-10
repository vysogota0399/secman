package blobs

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/server"
)

func TestBackend_createHandler(t *testing.T) {
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
		setup   func(*Backend, *server.LogicalRequest)
	}{
		{
			name: "successfully creates blob",
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &server.LogicalParams{
					Body: &MetadataBody{
						Metadata: map[string]string{
							"test": "value",
						},
					},
				},
			},
			want: &server.LogicalResponse{
				Status: http.StatusOK,
				Message: gin.H{
					"token": "", // Token will be generated randomly
				},
			},
			wantErr: false,
			setup: func(b *Backend, req *server.LogicalRequest) {
				// Create multipart form
				body := &bytes.Buffer{}
				writer := multipart.NewWriter(body)
				part, err := writer.CreateFormFile("file", "test.txt")
				if err != nil {
					t.Fatal(err)
				}
				part.Write([]byte("test content"))
				writer.Close()

				// Create request with multipart form
				httpReq, err := http.NewRequest("POST", "/", body)
				if err != nil {
					t.Fatal(err)
				}
				httpReq.Header.Set("Content-Type", writer.FormDataContentType())

				// Parse multipart form
				reader := multipart.NewReader(body, writer.Boundary())
				form, err := reader.ReadForm(0)
				if err != nil {
					t.Fatal(err)
				}

				// Set request in gin context
				req.Context.Request = httpReq
				req.Context.Request.MultipartForm = form

				// Mock S3 Create
				s3 := b.s3.(*MockS3)
				s3.EXPECT().
					Create(gomock.Any(), gomock.Any()).
					Return(nil)

				// Mock repository CreateBlob
				b.repo.storage.(*server.MockILogicalStorage).EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Mock metadata Update
				b.metadata.storage.(*server.MockBarrierStorage).EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "returns error when file is missing",
			args: args{
				ctx: context.Background(),
				req: &server.LogicalRequest{
					Context: &gin.Context{},
				},
				params: &server.LogicalParams{
					Body: &MetadataBody{
						Metadata: map[string]string{
							"test": "value",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			setup: func(b *Backend, req *server.LogicalRequest) {
				// Create empty request
				httpReq, err := http.NewRequest("POST", "/", nil)
				if err != nil {
					t.Fatal(err)
				}
				httpReq.Header.Set("Content-Type", "multipart/form-data")

				// Set request in gin context
				req.Context.Request = httpReq
				req.Context.Request.MultipartForm = &multipart.Form{
					File: make(map[string][]*multipart.FileHeader),
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			b, _, _ := NewTestBackend(t)

			if tt.setup != nil {
				tt.setup(b, tt.args.req)
			}

			got, err := b.createHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.createHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if got.Status != tt.want.Status {
					t.Errorf("Backend.createHandler() status = %v, want %v", got.Status, tt.want.Status)
				}
				if got.Message.(gin.H)["token"] == "" {
					t.Error("Backend.createHandler() token is empty")
				}
			}
		})
	}
}
