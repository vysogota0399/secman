package logopass

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/vysogota0399/secman/internal/secman"
	logopass_repositories "github.com/vysogota0399/secman/internal/secman/engines/logopass/repositories"
)

func TestBackend_getParamsHandler(t *testing.T) {
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
	}{
		{
			name: "returns params successfully",
			args: args{
				ctx:    context.Background(),
				req:    &secman.LogicalRequest{},
				params: &secman.LogicalParams{},
			},
			want: &secman.LogicalResponse{
				Status: 200,
				Message: &logopass_repositories.Params{
					TokenTTL:  time.Hour * 24,
					SecretKey: "test-secret-key",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewTestBackend(t)
			// Set up the expected params
			b.params = &logopass_repositories.Params{
				TokenTTL:  time.Hour * 24,
				SecretKey: "test-secret-key",
			}
			got, err := b.getParamsHandler(tt.args.ctx, tt.args.req, tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.getParamsHandler() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Backend.getParamsHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
