package bariers

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/cryptoutils"
)

// mockStorage implements secman.IStorage for testing
type mockStorage struct{}

func (m *mockStorage) Get(ctx context.Context, path string) (secman.PhysicalEntry, error) {
	return secman.PhysicalEntry{}, nil
}

func (m *mockStorage) Update(ctx context.Context, path string, value secman.PhysicalEntry, ttl time.Duration) error {
	return nil
}

func (m *mockStorage) Delete(ctx context.Context, path string) error {
	return nil
}

func (m *mockStorage) List(ctx context.Context, path string) ([]secman.PhysicalEntry, error) {
	return nil, nil
}

func TestNewPartsBuffer(t *testing.T) {
	type args struct {
		max int
	}
	tests := []struct {
		name    string
		args    args
		want    *PartsBuffer
		wantErr bool
	}{
		{
			name: "create buffer with max capacity 3",
			args: args{max: 3},
			want: &PartsBuffer{
				Parts: make([][]byte, 0, 3),
				max:   3,
			},
			wantErr: false,
		},
		{
			name:    "create buffer with max capacity 0",
			args:    args{max: 0},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPartsBuffer(tt.args.max)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPartsBuffer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if got.max != tt.want.max {
				t.Errorf("NewPartsBuffer().max = %v, want %v", got.max, tt.want.max)
			}
			if cap(got.Parts) != cap(tt.want.Parts) {
				t.Errorf("NewPartsBuffer().Parts capacity = %v, want %v", cap(got.Parts), cap(tt.want.Parts))
			}
			if len(got.Parts) != len(tt.want.Parts) {
				t.Errorf("NewPartsBuffer().Parts length = %v, want %v", len(got.Parts), len(tt.want.Parts))
			}
		})
	}
}

func TestPartsBuffer_Add(t *testing.T) {
	type fields struct {
		Parts [][]byte
		max   int
	}
	type args struct {
		part []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "add part when buffer is empty",
			fields: fields{
				Parts: make([][]byte, 0, 3),
				max:   3,
			},
			args: args{
				part: []byte("test1"),
			},
			want: false,
		},
		{
			name: "add part when buffer has one part",
			fields: fields{
				Parts: [][]byte{[]byte("test1")},
				max:   3,
			},
			args: args{
				part: []byte("test2"),
			},
			want: false,
		},
		{
			name: "add part when buffer is full",
			fields: fields{
				Parts: [][]byte{[]byte("test1"), []byte("test2")},
				max:   3,
			},
			args: args{
				part: []byte("test3"),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := &PartsBuffer{
				Parts: tt.fields.Parts,
				mtx:   sync.RWMutex{},
				max:   tt.fields.max,
			}
			if got := pb.Add(tt.args.part); got != tt.want {
				t.Errorf("PartsBuffer.Add() = %v, want %v", got, tt.want)
			}
			// Verify the part was added
			if len(pb.Parts) != len(tt.fields.Parts)+1 {
				t.Errorf("PartsBuffer.Parts length = %v, want %v", len(pb.Parts), len(tt.fields.Parts)+1)
			}
			// Verify the last part is the one we added
			if !reflect.DeepEqual(pb.Parts[len(pb.Parts)-1], tt.args.part) {
				t.Errorf("PartsBuffer.Parts last element = %v, want %v", pb.Parts[len(pb.Parts)-1], tt.args.part)
			}
		})
	}
}

func TestPartsBuffer_Clear(t *testing.T) {
	type fields struct {
		Parts [][]byte
		max   int
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "clear empty buffer",
			fields: fields{
				Parts: make([][]byte, 0, 3),
				max:   3,
			},
		},
		{
			name: "clear full buffer",
			fields: fields{
				Parts: [][]byte{[]byte("test1"), []byte("test2"), []byte("test3")},
				max:   3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := &PartsBuffer{
				Parts: tt.fields.Parts,
				mtx:   sync.RWMutex{},
				max:   tt.fields.max,
			}
			originalCapacity := cap(pb.Parts)
			pb.Clear()

			// Verify the buffer is empty
			if len(pb.Parts) != 0 {
				t.Errorf("PartsBuffer.Clear() length = %v, want 0", len(pb.Parts))
			}

			// Verify the capacity is maintained
			if cap(pb.Parts) != originalCapacity {
				t.Errorf("PartsBuffer.Clear() capacity = %v, want %v", cap(pb.Parts), originalCapacity)
			}
		})
	}
}

func TestNewAes256Barier(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	type args struct {
		storage secman.IStorage
		log     *logging.ZapLogger
		keyring *secman.Keyring
	}
	tests := []struct {
		name    string
		args    args
		want    *Aes256Barier
		wantErr bool
	}{
		{
			name: "create new barrier with valid inputs",
			args: args{
				storage: secman.NewMockIStorage(ctrl),
				log:     &logging.ZapLogger{},
				keyring: secman.NewKeyring(),
			},
			want: &Aes256Barier{
				storage:                 secman.NewMockIStorage(ctrl),
				log:                     &logging.ZapLogger{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAes256Barier(tt.args.storage, tt.args.log, tt.args.keyring)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAes256Barier() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			// Verify the barrier is sealed
			if !got.sealed.Load() {
				t.Error("NewAes256Barier() barrier should be sealed")
			}

			// Verify parts buffer is initialized correctly
			if got.partsBuffer == nil {
				t.Error("NewAes256Barier() partsBuffer should not be nil")
			}
			if got.partsBuffer.max != tt.want.thresholdsCoundRequired {
				t.Errorf("NewAes256Barier() partsBuffer.max = %v, want %v", got.partsBuffer.max, tt.want.thresholdsCoundRequired)
			}

			// Verify other fields
			if got.thresholdsCoundRequired != tt.want.thresholdsCoundRequired {
				t.Errorf("NewAes256Barier() thresholdsCoundRequired = %v, want %v", got.thresholdsCoundRequired, tt.want.thresholdsCoundRequired)
			}
			if got.partsCount != tt.want.partsCount {
				t.Errorf("NewAes256Barier() partsCount = %v, want %v", got.partsCount, tt.want.partsCount)
			}
		})
	}
}

func TestAes256Barier_Init(t *testing.T) {
	keyring := secman.NewKeyring()

	barrier, storage := NewBarier(t, keyring)

	storage.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

	ssskeys, err := barrier.Init(context.Background())
	assert.NoError(t, err)

	assert.Equal(t, barrier.partsCount, len(ssskeys), "sss keys count should be equal to parts count")
	assert.Equal(t, 0, len(keyring.Keys), "keyring should be empty")
	assert.Nil(t, keyring.RootKey, "root key should be nil")
}

func TestAes256Barier_encript_decript(t *testing.T) {
	key := &secman.Key{
		ID:  1,
		Raw: cryptoutils.GenerateRandom(32),
	}

	message := []byte("test message")

	barrier, _ := NewBarier(t, nil)

	encripted, err := barrier.encript(message, key)
	assert.NoError(t, err)

	decripted, err := barrier.decript(encripted, key)
	assert.NoError(t, err)

	assert.Equal(t, message, decripted)
}

func NewBarier(t *testing.T, keyring *secman.Keyring) (*Aes256Barier, *secman.MockIStorage) {
	t.Helper()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	storage := secman.NewMockIStorage(ctrl)
	barrier, err := NewAes256Barier(storage, secman.NewLogger(t), keyring)
	assert.NoError(t, err)

	return barrier, storage
}

func TestAes256Barier_actualKey(t *testing.T) {
	keyring := secman.NewKeyring()

	k1 := keyring.GenerateKey([]byte("key1"))
	keyring.AddKey(k1.Raw, k1.ID)

	k2 := keyring.GenerateKey([]byte("key2"))
	keyring.AddKey(k2.Raw, k2.ID)

	k3 := keyring.GenerateKey([]byte("key3"))
	keyring.AddKey(k3.Raw, k3.ID)

	barrier, _ := NewBarier(t, keyring)

	got := barrier.actualKey()
	assert.Equal(t, k3.Raw, got.Raw, "actual key should be equal to the key we set")
}

func TestAes256Barier_keyFromCiphertext(t *testing.T) {
	keyring := secman.NewKeyring()
	barrier, _ := NewBarier(t, keyring)

	k1 := barrier.generateKey()
	key1 := barrier.keyring.GenerateKey(k1)
	barrier.keyring.AddKey(key1.Raw, key1.ID)

	encripted, err := barrier.encript([]byte("seret message"), key1)
	assert.NoError(t, err)

	got, err := barrier.keyFromCiphertext(encripted)
	assert.NoError(t, err)
	assert.Equal(t, key1.Raw, got.Raw, "key should be equal to the key we set")

	k2 := barrier.generateKey()
	key2 := barrier.keyring.GenerateKey(k2)

	encripted, err = barrier.encript([]byte("seret message"), key2)
	assert.NoError(t, err)

	got, err = barrier.keyFromCiphertext(encripted)
	assert.Error(t, err, "there are not such key in keyring")
	assert.Nil(t, got, "key should be nil")
}

func TestAes256Barier_Unseal(t *testing.T) {
	type args struct {
		ctx context.Context
		key []byte
	}
	tests := []struct {
		name    string
		args    *args
		want    bool
		wantErr bool
		prepare func(b *Aes256Barier, a *args, storage *secman.MockIStorage)
	}{
		{
			name: "already unsealed barrier",
			args: &args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			want:    false,
			wantErr: true,
			prepare: func(b *Aes256Barier, a *args, storage *secman.MockIStorage) {
				b.sealed.Store(false)
			},
		},
		{
			name: "not enough parts collected",
			args: &args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			want:    false,
			wantErr: false,
			prepare: func(b *Aes256Barier, a *args, storage *secman.MockIStorage) {
				b.sealed.Store(true)
				b.partsBuffer.Add([]byte("part1"))
			},
		},
		{
			name: "invalid keys",
			args: &args{
				ctx: context.Background(),
				key: []byte("test-key-invalid"),
			},
			prepare: func(b *Aes256Barier, a *args, storage *secman.MockIStorage) {
				b.sealed.Store(true)

				storage.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				keys, err := b.Init(a.ctx)
				if err != nil {
					t.Fatalf("Failed to initialize barrier: %v", err)
				}

				b.partsBuffer.Add(keys[0])
				b.partsBuffer.Add(keys[1])
				a.key = []byte("test-key-invalid")
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "successful unseal",
			args: &args{
				ctx: context.Background(),
				key: []byte("test-key"),
			},
			want:    true,
			wantErr: false,
			prepare: func(b *Aes256Barier, a *args, storage *secman.MockIStorage) {
				b.sealed.Store(true)

				var tmpValue secman.PhysicalEntry
				storage.EXPECT().Update(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(ctx context.Context, path string, value secman.PhysicalEntry, ttl time.Duration) error {
					tmpValue = value
					return nil
				})

				storage.EXPECT().List(gomock.Any(), gomock.Any()).Return([]secman.PhysicalEntry{tmpValue}, nil).DoAndReturn(func(ctx context.Context, path string) ([]secman.PhysicalEntry, error) {
					return []secman.PhysicalEntry{tmpValue}, nil
				})

				keys, err := b.Init(a.ctx)
				if err != nil {
					t.Fatalf("Failed to initialize barrier: %v", err)
				}

				b.partsBuffer.Add(keys[0])
				b.partsBuffer.Add(keys[1])
				a.key = keys[2]
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := secman.NewMockIStorage(ctrl)
			b, err := NewAes256Barier(storage, secman.NewLogger(t), secman.NewKeyring())
			if err != nil {
				t.Fatalf("Failed to create barrier: %v", err)
			}

			if tt.prepare != nil {
				tt.prepare(b, tt.args, storage)
			}

			got, err := b.Unseal(tt.args.ctx, tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("Aes256Barier.Unseal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Aes256Barier.Unseal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAes256Barier_isSealed(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
		partsBuffer             *PartsBuffer
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "barrier is sealed",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			want: true,
		},
		{
			name: "barrier is unsealed",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Aes256Barier{
				storage:                 tt.fields.storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             tt.fields.partsBuffer,
			}
			// Set the sealed state based on the test case
			b.sealed.Store(tt.want)
			if got := b.isSealed(); got != tt.want {
				t.Errorf("Aes256Barier.isSealed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAes256Barier_List(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
		partsBuffer             *PartsBuffer
	}
	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []secman.Entry
		wantErr bool
		prepare func(b *Aes256Barier, storage *secman.MockIStorage)
	}{
		{
			name: "barrier is sealed",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    nil,
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(true)
			},
		},
		{
			name: "storage returns error",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    nil,
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)
				storage.EXPECT().
					List(gomock.Any(), "test/path").
					Return(nil, assert.AnError)
			},
		},
		{
			name: "successful list with decryption",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want: []secman.Entry{
				{
					Value: "decrypted value 1",
				},
				{
					Value: "decrypted value 2",
				},
			},
			wantErr: false,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)

				// Generate a key for encryption/decryption
				key := b.generateKey()
				keyObj := b.keyring.GenerateKey(key)
				b.keyring.AddKey(keyObj.Raw, keyObj.ID)

				// Create encrypted entries
				encrypted1, _ := b.encript([]byte("decrypted value 1"), keyObj)
				encrypted2, _ := b.encript([]byte("decrypted value 2"), keyObj)

				storage.EXPECT().
					List(gomock.Any(), "test/path").
					Return([]secman.PhysicalEntry{
						{
							Value: encrypted1,
						},
						{
							Value: encrypted2,
						},
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := secman.NewMockIStorage(ctrl)
			b := &Aes256Barier{
				storage:                 storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             tt.fields.partsBuffer,
			}

			if tt.prepare != nil {
				tt.prepare(b, storage)
			}

			got, err := b.List(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Aes256Barier.List() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Aes256Barier.List() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAes256Barier_GetOk(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
		partsBuffer             *PartsBuffer
	}
	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    secman.Entry
		want1   bool
		wantErr bool
		prepare func(b *Aes256Barier, storage *secman.MockIStorage)
	}{
		{
			name: "barrier is sealed",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			want1:   false,
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(true)
			},
		},
		{
			name: "entry not found",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			want1:   false,
			wantErr: false,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{}, secman.ErrEntryNotFound)
			},
		},
		{
			name: "storage returns error",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want:    secman.Entry{},
			want1:   false,
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)
				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{}, assert.AnError)
			},
		},
		{
			name: "successful get with decryption",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			want: secman.Entry{
				Value: "decrypted value",
				Path:  "test/path",
			},
			want1:   true,
			wantErr: false,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)

				// Generate a key for encryption/decryption
				key := b.generateKey()
				keyObj := b.keyring.GenerateKey(key)
				b.keyring.AddKey(keyObj.Raw, keyObj.ID)

				// Create encrypted entry
				encrypted, _ := b.encript([]byte("decrypted value"), keyObj)

				storage.EXPECT().
					Get(gomock.Any(), "test/path").
					Return(secman.PhysicalEntry{
						Value: encrypted,
						Path:  "test/path",
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := secman.NewMockIStorage(ctrl)
			b := &Aes256Barier{
				storage:                 storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             tt.fields.partsBuffer,
			}

			if tt.prepare != nil {
				tt.prepare(b, storage)
			}

			got, got1, err := b.GetOk(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Aes256Barier.GetOk() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Aes256Barier.GetOk() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("Aes256Barier.GetOk() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestAes256Barier_Get(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
		partsBuffer             *PartsBuffer
	}
	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    secman.Entry
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Aes256Barier{
				storage:                 tt.fields.storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             tt.fields.partsBuffer,
			}
			got, err := b.Get(tt.args.ctx, tt.args.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Aes256Barier.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Aes256Barier.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAes256Barier_Update(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
		partsBuffer             *PartsBuffer
	}
	type args struct {
		ctx   context.Context
		path  string
		entry secman.Entry
		ttl   time.Duration
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(b *Aes256Barier, storage *secman.MockIStorage)
	}{
		{
			name: "barrier is sealed",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:   context.Background(),
				path:  "test/path",
				entry: secman.Entry{Value: "test value"},
				ttl:   time.Hour,
			},
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(true)
			},
		},
		{
			name: "storage returns error",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:   context.Background(),
				path:  "test/path",
				entry: secman.Entry{Value: "test value"},
				ttl:   time.Hour,
			},
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)

				// Generate a key for encryption
				key := b.generateKey()
				keyObj := b.keyring.GenerateKey(key)
				b.keyring.AddKey(keyObj.Raw, keyObj.ID)

				storage.EXPECT().
					Update(gomock.Any(), "test/path", gomock.Any(), time.Hour).
					Return(assert.AnError)
			},
		},
		{
			name: "successful update",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:   context.Background(),
				path:  "test/path",
				entry: secman.Entry{Value: "test value"},
				ttl:   time.Hour,
			},
			wantErr: false,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)

				// Generate a key for encryption
				key := b.generateKey()
				keyObj := b.keyring.GenerateKey(key)
				b.keyring.AddKey(keyObj.Raw, keyObj.ID)

				storage.EXPECT().
					Update(gomock.Any(), "test/path", gomock.Any(), time.Hour).
					Return(nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := secman.NewMockIStorage(ctrl)
			b := &Aes256Barier{
				storage:                 storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             tt.fields.partsBuffer,
			}

			if tt.prepare != nil {
				tt.prepare(b, storage)
			}

			if err := b.Update(tt.args.ctx, tt.args.path, tt.args.entry, tt.args.ttl); (err != nil) != tt.wantErr {
				t.Errorf("Aes256Barier.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAes256Barier_Delete(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
		partsBuffer             *PartsBuffer
	}
	type args struct {
		ctx  context.Context
		path string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(b *Aes256Barier, storage *secman.MockIStorage)
	}{
		{
			name: "barrier is sealed",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(true)
			},
		},
		{
			name: "storage returns error",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			wantErr: true,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)
				storage.EXPECT().
					Delete(gomock.Any(), "test/path").
					Return(assert.AnError)
			},
		},
		{
			name: "successful delete",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
				partsBuffer:             &PartsBuffer{},
			},
			args: args{
				ctx:  context.Background(),
				path: "test/path",
			},
			wantErr: false,
			prepare: func(b *Aes256Barier, storage *secman.MockIStorage) {
				b.sealed.Store(false)
				storage.EXPECT().
					Delete(gomock.Any(), "test/path").
					Return(nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			storage := secman.NewMockIStorage(ctrl)
			b := &Aes256Barier{
				storage:                 storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             tt.fields.partsBuffer,
			}

			if tt.prepare != nil {
				tt.prepare(b, storage)
			}

			if err := b.Delete(tt.args.ctx, tt.args.path); (err != nil) != tt.wantErr {
				t.Errorf("Aes256Barier.Delete() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAes256Barier_Info(t *testing.T) {
	type fields struct {
		storage                 secman.IStorage
		log                     *logging.ZapLogger
		sealed                  *atomic.Bool
		keyring                 *secman.Keyring
		thresholdsCoundRequired int
		partsCount              int
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		prepare func(b *Aes256Barier)
	}{
		{
			name: "no parts collected",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
			},
			want: "AES256 SSS keys: 0/3",
			prepare: func(b *Aes256Barier) {
				// No parts added to buffer
			},
		},
		{
			name: "some parts collected",
			fields: fields{
				storage:                 &mockStorage{},
				log:                     &logging.ZapLogger{},
				sealed:                  &atomic.Bool{},
				keyring:                 secman.NewKeyring(),
				thresholdsCoundRequired: 3,
				partsCount:              5,
			},
			want: "AES256 SSS keys: 2/3",
			prepare: func(b *Aes256Barier) {
				b.partsBuffer.Add([]byte("part1"))
				b.partsBuffer.Add([]byte("part2"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			partsBuffer, err := NewPartsBuffer(tt.fields.thresholdsCoundRequired)
			if err != nil {
				t.Fatalf("NewPartsBuffer() error = %v", err)
			}

			b := &Aes256Barier{
				storage:                 tt.fields.storage,
				log:                     tt.fields.log,
				sealed:                  tt.fields.sealed,
				keyring:                 tt.fields.keyring,
				thresholdsCoundRequired: tt.fields.thresholdsCoundRequired,
				partsCount:              tt.fields.partsCount,
				partsBuffer:             partsBuffer,
			}

			if tt.prepare != nil {
				tt.prepare(b)
			}

			if got := b.Info(); got != tt.want {
				t.Errorf("Aes256Barier.Info() = %v, want %v", got, tt.want)
			}
		})
	}
}
