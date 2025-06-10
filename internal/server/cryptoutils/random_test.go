package cryptoutils

import (
	"testing"
)

func TestGenerateRandom(t *testing.T) {
	type args struct {
		size int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "generate 16 bytes",
			args: args{size: 16},
			want: make([]byte, 16),
		},
		{
			name: "generate 32 bytes",
			args: args{size: 32},
			want: make([]byte, 32),
		},
		{
			name: "generate 64 bytes",
			args: args{size: 64},
			want: make([]byte, 64),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateRandom(tt.args.size)
			if len(got) != tt.args.size {
				t.Errorf("GenerateRandom() length = %v, want %v", len(got), tt.args.size)
			}
		})
	}
}
