package pci_dss

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

func TestBackend_PostUnseal(t *testing.T) {
	type fields struct {
		beMtx    sync.RWMutex
		exist    *atomic.Bool
		router   *secman.BackendRouter
		repo     *Repository
		metadata *MetadataRepository
		lg       *logging.ZapLogger
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				beMtx:    tt.fields.beMtx,
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     tt.fields.repo,
				metadata: tt.fields.metadata,
				lg:       tt.fields.lg,
			}
			if err := b.PostUnseal(tt.args.ctx); (err != nil) != tt.wantErr {
				t.Errorf("Backend.PostUnseal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBackend_Enable(t *testing.T) {
	ctrl := secman.NewController(t)
	defer ctrl.Finish()

	lg := secman.NewLogger(t)

	type fields struct {
		exist    *atomic.Bool
		router   *secman.BackendRouter
		metadata *MetadataRepository
	}
	type args struct {
		ctx context.Context
		req *secman.LogicalRequest
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
			name: "successful enable",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusOK,
				Message: "pci_dss enabled",
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "already enabled",
			fields: &fields{
				exist:    func() *atomic.Bool { b := &atomic.Bool{}; b.Store(true); return b }(),
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
			},
			want: &secman.LogicalResponse{
				Status:  http.StatusNotModified,
				Message: "pci_dss: already enabled",
			},
			wantErr: false,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				b.exist.Store(true)
			},
		},
		{
			name: "enable error",
			fields: &fields{
				exist:    &atomic.Bool{},
				router:   nil,
				metadata: &MetadataRepository{},
			},
			args: args{
				ctx: context.Background(),
				req: &secman.LogicalRequest{},
			},
			want:    nil,
			wantErr: true,
			prepare: func(mockStorage *secman.MockILogicalStorage, b *Backend) {
				mockStorage.EXPECT().
					Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
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

			got, err := b.Enable(tt.args.ctx, tt.args.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestBackend_Paths(t *testing.T) {
	type fields struct {
		exist    *atomic.Bool
		router   *secman.BackendRouter
		repo     *Repository
		metadata *MetadataRepository
		lg       *logging.ZapLogger
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]map[string]*secman.Path
	}{
		{
			name: "check all handlers are initialized",
			fields: fields{
				exist:    &atomic.Bool{},
				router:   nil,
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				lg:       &logging.ZapLogger{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Backend{
				exist:    tt.fields.exist,
				router:   tt.fields.router,
				repo:     tt.fields.repo,
				metadata: tt.fields.metadata,
				lg:       tt.fields.lg,
			}
			paths := b.Paths()

			// Check GET handlers
			if paths[http.MethodGet] == nil {
				t.Error("GET paths map is nil")
			}
			if paths[http.MethodGet][PATH+"/:card_token/metadata"].Handler == nil {
				t.Error("ShowMetadataHandler is nil")
			}
			if paths[http.MethodGet][PATH+"/:card_token"].Handler == nil {
				t.Error("ShowPanHandler is nil")
			}
			if paths[http.MethodGet][PATH+"/:card_token/cardholder_name/:cardholder_name_token"].Handler == nil {
				t.Error("ShowCardholderNameHandler is nil")
			}
			if paths[http.MethodGet][PATH+"/:card_token/expiry_date/:expiry_date_token"].Handler == nil {
				t.Error("ShowExpiryDateHandler is nil")
			}
			if paths[http.MethodGet][PATH+"/:card_token/security_code/:security_code_token"].Handler == nil {
				t.Error("ShowSecurityCodeHandler is nil")
			}

			// Check POST handler
			if paths[http.MethodPost] == nil {
				t.Error("POST paths map is nil")
			}
			if paths[http.MethodPost][PATH].Handler == nil {
				t.Error("CreateHandler is nil")
			}

			// Check DELETE handler
			if paths[http.MethodDelete] == nil {
				t.Error("DELETE paths map is nil")
			}
			if paths[http.MethodDelete][PATH+"/:card_token"].Handler == nil {
				t.Error("DeleteHandler is nil")
			}

			// Check PUT handler
			if paths[http.MethodPut] == nil {
				t.Error("PUT paths map is nil")
			}
			if paths[http.MethodPut][PATH+"/:card_token/metadata"].Handler == nil {
				t.Error("UpdateMetadataHandler is nil")
			}

			// Check that all paths have descriptions
			for method, methodPaths := range paths {
				for path, pathInfo := range methodPaths {
					if pathInfo.Description == "" {
						t.Errorf("Path %s %s has no description", method, path)
					}
				}
			}

			// Check fields for paths that require them
			checkFields := func(path string, fields []secman.Field, expectedNames []string) {
				if len(fields) != len(expectedNames) {
					t.Errorf("Path %s should have exactly %d fields, got %d", path, len(expectedNames), len(fields))
					return
				}
				for i, name := range expectedNames {
					if fields[i].Name != name {
						t.Errorf("Path %s field %d name should be %s, got %s", path, i, name, fields[i].Name)
					}
					if fields[i].Description == "" {
						t.Errorf("Path %s field %d description is empty", path, i)
					}
				}
			}

			// Check fields for various paths
			checkFields(PATH+"/:card_token/metadata", paths[http.MethodGet][PATH+"/:card_token/metadata"].Fields, []string{"card_token"})
			checkFields(PATH+"/:card_token", paths[http.MethodGet][PATH+"/:card_token"].Fields, []string{"card_token", "pan_token"})
			checkFields(PATH+"/:card_token/cardholder_name/:cardholder_name_token", paths[http.MethodGet][PATH+"/:card_token/cardholder_name/:cardholder_name_token"].Fields, []string{"card_token", "cardholder_name_token"})
			checkFields(PATH+"/:card_token/expiry_date/:expiry_date_token", paths[http.MethodGet][PATH+"/:card_token/expiry_date/:expiry_date_token"].Fields, []string{"card_token", "expiry_date_token"})
			checkFields(PATH+"/:card_token/security_code/:security_code_token", paths[http.MethodGet][PATH+"/:card_token/security_code/:security_code_token"].Fields, []string{"card_token", "security_code_token"})
			checkFields(PATH+"/:card_token", paths[http.MethodDelete][PATH+"/:card_token"].Fields, []string{"card_token"})
			checkFields(PATH+"/:card_token/metadata", paths[http.MethodPut][PATH+"/:card_token/metadata"].Fields, []string{"card_token"})

			// Check that POST / has a body function
			if paths[http.MethodPost][PATH].Body == nil {
				t.Error("POST / path should have a body function")
			}

			// Check that PUT /:card_token/metadata has a body function
			if paths[http.MethodPut][PATH+"/:card_token/metadata"].Body == nil {
				t.Error("PUT /:card_token/metadata path should have a body function")
			}
		})
	}
}

func TestNewBackend(t *testing.T) {
	type args struct {
		lg       *logging.ZapLogger
		repo     *Repository
		metadata *MetadataRepository
	}
	tests := []struct {
		name string
		args args
		want *Backend
	}{
		{
			name: "successful initialization",
			args: args{
				lg:       &logging.ZapLogger{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
			},
			want: &Backend{
				lg:       &logging.ZapLogger{},
				repo:     &Repository{},
				metadata: &MetadataRepository{},
				exist:    &atomic.Bool{},
				beMtx:    sync.RWMutex{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewBackend(tt.args.lg, tt.args.repo, tt.args.metadata)

			// Check that the basic fields are set correctly
			if got.lg != tt.args.lg {
				t.Errorf("NewBackend().lg = %v, want %v", got.lg, tt.args.lg)
			}
			if got.repo != tt.args.repo {
				t.Errorf("NewBackend().repo = %v, want %v", got.repo, tt.args.repo)
			}
			if got.metadata != tt.args.metadata {
				t.Errorf("NewBackend().metadata = %v, want %v", got.metadata, tt.args.metadata)
			}

			// Check that exist is initialized as false
			if got.exist.Load() {
				t.Error("NewBackend().exist should be initialized as false")
			}

			// Check that router is nil initially
			if got.router != nil {
				t.Error("NewBackend().router should be nil initially")
			}
		})
	}
}
