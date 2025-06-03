package logopass

import (
	"testing"

	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func TestBackend_Authorize(t *testing.T) {
	type args struct {
		c *gin.Context
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "skip auth for login path",
			args: args{
				c: &gin.Context{
					Request: &http.Request{
						Method: "POST",
						URL:    &url.URL{Path: "/auth/logopass/login"},
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "skip auth for register path",
			args: args{
				c: &gin.Context{
					Request: &http.Request{
						Method: "POST",
						URL:    &url.URL{Path: "/auth/logopass/register"},
					},
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "no auth header",
			args: args{
				c: &gin.Context{
					Request: &http.Request{
						Method: "GET",
						URL:    &url.URL{Path: "/auth/logopass/"},
					},
				},
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewTestBackend(t)
			got, err := b.Authorize(tt.args.c)
			if (err != nil) != tt.wantErr {
				t.Errorf("Backend.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Backend.Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}
