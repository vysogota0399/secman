package pcidss

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

func TestBackend_CreateHandler(t *testing.T) {
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
			name: "invalid card data - missing PAN",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "PAN is required"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {},
		},
		{
			name: "invalid card data - missing cardholder name",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:          "4111111111111111",
							ExpiryDate:   "2025-12-31T23:59:59.999999999Z",
							SecurityCode: "123",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "cardholder name is required"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)
			},
		},
		{
			name: "invalid card data - missing expiry date",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							SecurityCode:   "123",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "expiry date is required"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)
			},
		},
		{
			name: "invalid card data - invalid expiry date format",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31",
							SecurityCode:   "123",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "invalid expiry date format, expected RFC3339Nano"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)
			},
		},
		{
			name: "invalid card data - missing security code",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "security code is required"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)
			},
		},
		{
			name: "PAN already exists",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "\nsuch PAN already exists"},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)

				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{Value: "4111111111111111"}, true, nil)
			},
		},
		{
			name: "storage error during PAN creation",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)

				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)
			},
		},
		{
			name: "successful card creation",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want: &secman.LogicalResponse{
				Status: http.StatusOK,
				Message: gin.H{
					"pan":             gomock.Any(),
					"cardholder_name": gomock.Any(),
					"expiry_date":     gomock.Any(),
					"security_code":   gomock.Any(),
				},
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				// Initialize metadata repository with mock storage
				b.metadata = NewMetadataRepository(mockStorage)

				// PAN token check
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				// PAN creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Metadata update
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Cardholder name creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Expiry date creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Security code creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "type cast error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: "invalid body type",
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)
			},
		},
		{
			name: "metadata update error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)

				// PAN token check
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				// PAN creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Metadata update error
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)

				// Cleanup expectations - PAN token deletion
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "cardholder name creation error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)

				// PAN token check
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				// PAN creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Metadata update
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Cardholder name creation error
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)

				// Cleanup expectations - PAN token deletion
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "expiry date creation error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)

				// PAN token check
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				// PAN creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Metadata update
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Cardholder name creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Expiry date creation error
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)

				// Cleanup expectations - cardholder name and PAN token deletion
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "security code creation error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)

				// PAN token check
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				// PAN creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Metadata update
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Cardholder name creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Expiry date creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Security code creation error
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)

				// Cleanup expectations - expiry date, cardholder name, and PAN token deletion
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "cleanup error during failure",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
				params: &secman.LogicalParams{
					Body: &CreateCardBody{
						CardData: CardData{
							PAN:            "4111111111111111",
							CardholderName: "John Doe",
							ExpiryDate:     "2025-12-31T23:59:59.999999999Z",
							SecurityCode:   "123",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.metadata = NewMetadataRepository(mockStorage)

				// PAN token check
				mockStorage.EXPECT().
					GetOk(gomock.Any(), gomock.Any()).
					Return(secman.Entry{}, false, nil)

				// PAN creation
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Metadata update
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)

				// Cardholder name creation error
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(assert.AnError)

				// Cleanup error - PAN token deletion
				mockStorage.EXPECT().
					Delete(gomock.Any(), gomock.Any()).
					Return(assert.AnError)
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

			got, err := b.CreateHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify response structure and token formats
				assert.Equal(t, tt.want.Status, got.Status)
				assert.NotNil(t, got.Message)
				message, ok := got.Message.(gin.H)
				assert.True(t, ok)

				if tt.want.Status == http.StatusOK {
					assert.Len(t, message, 4)
					assert.Contains(t, message, "pan")
					assert.Contains(t, message, "cardholder_name")
					assert.Contains(t, message, "expiry_date")
					assert.Contains(t, message, "security_code")

					// Verify token formats
					pan, ok := message["pan"].(string)
					assert.True(t, ok)
					assert.Len(t, pan, 64) // SHA-256 hash length

					cardholderName, ok := message["cardholder_name"].(string)
					assert.True(t, ok)
					assert.NotEmpty(t, cardholderName)

					expiryDate, ok := message["expiry_date"].(string)
					assert.True(t, ok)
					assert.NotEmpty(t, expiryDate)

					securityCode, ok := message["security_code"].(string)
					assert.True(t, ok)
					assert.NotEmpty(t, securityCode)
				} else {
					assert.Equal(t, tt.want.Message, got.Message)
				}
			}
		})
	}
}
