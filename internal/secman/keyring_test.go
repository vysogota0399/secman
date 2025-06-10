package secman

import (
	"reflect"
	"sync"
	"testing"
)

func TestNewKeyring(t *testing.T) {
	tests := []struct {
		name string
		want *Keyring
	}{
		{
			name: "create new keyring",
			want: &Keyring{
				Keys:     make(map[uint32]*Key),
				keyMtx:   sync.RWMutex{},
				actualID: 0,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewKeyring(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewKeyring() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyring_ActualID(t *testing.T) {
	type fields struct {
		RootKey  *Key
		actualID uint32
		Keys     map[uint32]*Key
	}
	tests := []struct {
		name   string
		fields fields
		want   uint32
	}{
		{
			name: "get actual id",
			fields: fields{
				actualID: 42,
				Keys:     make(map[uint32]*Key),
			},
			want: 42,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := NewKeyring()
			kr.actualID = tt.fields.actualID
			kr.Keys = tt.fields.Keys
			if got := kr.ActualID(); got != tt.want {
				t.Errorf("Keyring.ActualID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyring_GetKey(t *testing.T) {
	type fields struct {
		RootKey  *Key
		actualID uint32
		Keys     map[uint32]*Key
	}
	type args struct {
		id uint32
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Key
	}{
		{
			name: "get existing key",
			fields: fields{
				actualID: 1,
				Keys: map[uint32]*Key{
					1: {
						ID:     1,
						Raw:    []byte("test key"),
						Status: KeyStatusActive,
					},
				},
			},
			args: args{
				id: 1,
			},
			want: &Key{
				ID:     1,
				Raw:    []byte("test key"),
				Status: KeyStatusActive,
			},
		},
		{
			name: "get non-existent key",
			fields: fields{
				actualID: 1,
				Keys:     make(map[uint32]*Key),
			},
			args: args{
				id: 1,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := NewKeyring()
			k.actualID = tt.fields.actualID
			k.Keys = tt.fields.Keys

			if got := k.GetKey(tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Keyring.GetKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyring_SetRootKey(t *testing.T) {
	type fields struct {
		RootKey  *Key
		actualID uint32
		Keys     map[uint32]*Key
	}
	type args struct {
		key *Key
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "set root key",
			fields: fields{
				actualID: 0,
				Keys:     make(map[uint32]*Key),
			},
			args: args{
				key: &Key{
					ID:     0,
					Raw:    []byte("root key"),
					Status: KeyStatusActive,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := NewKeyring()
			kr.actualID = tt.fields.actualID
			kr.Keys = tt.fields.Keys
			kr.SetRootKey(tt.args.key)
			if !reflect.DeepEqual(kr.RootKey, tt.args.key) {
				t.Errorf("Keyring.SetRootKey() = %v, want %v", kr.RootKey, tt.args.key)
			}
		})
	}
}

func TestKeyring_AddKey(t *testing.T) {
	type fields struct {
		RootKey  *Key
		actualID uint32
		Keys     map[uint32]*Key
	}
	type args struct {
		key []byte
		id  uint32
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Key
	}{
		{
			name: "add new key",
			fields: fields{
				actualID: 0,
				Keys:     make(map[uint32]*Key),
			},
			args: args{
				key: []byte("test key"),
				id:  1,
			},
			want: &Key{
				ID:     1,
				Raw:    []byte("test key"),
				Status: KeyStatusActive,
			},
		},
		{
			name: "add key with existing id",
			fields: fields{
				actualID: 0,
				Keys: map[uint32]*Key{
					1: {
						ID:     1,
						Raw:    []byte("old key"),
						Status: KeyStatusActive,
					},
				},
			},
			args: args{
				key: []byte("new key"),
				id:  1,
			},
			want: &Key{
				ID:     1,
				Raw:    []byte("new key"),
				Status: KeyStatusActive,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := NewKeyring()
			kr.actualID = tt.fields.actualID
			kr.Keys = tt.fields.Keys
			if got := kr.AddKey(tt.args.key, tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Keyring.AddKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKeyring_GenerateKey(t *testing.T) {
	type fields struct {
		RootKey  *Key
		actualID uint32
		Keys     map[uint32]*Key
	}
	type args struct {
		b []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *Key
	}{
		{
			name: "generate first key",
			fields: fields{
				actualID: 0,
				Keys:     make(map[uint32]*Key),
			},
			args: args{
				b: []byte("test key"),
			},
			want: &Key{
				ID:     1,
				Raw:    []byte("test key"),
				Status: KeyStatusActive,
			},
		},
		{
			name: "generate key with existing key",
			fields: fields{
				actualID: 1,
				Keys: map[uint32]*Key{
					1: {
						ID:     1,
						Raw:    []byte("old key"),
						Status: KeyStatusActive,
					},
				},
			},
			args: args{
				b: []byte("new key"),
			},
			want: &Key{
				ID:     2,
				Raw:    []byte("new key"),
				Status: KeyStatusActive,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kr := NewKeyring()
			kr.actualID = tt.fields.actualID
			kr.Keys = tt.fields.Keys
			if got := kr.GenerateKey(tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Keyring.GenerateKey() = %v, want %v", got, tt.want)
			}
			// Verify that previous key was marked as inactive
			if tt.fields.actualID > 0 {
				if prevKey := kr.Keys[tt.fields.actualID]; prevKey != nil && prevKey.Status != KeyStatusInactive {
					t.Errorf("Previous key status = %v, want %v", prevKey.Status, KeyStatusInactive)
				}
			}
		})
	}
}
