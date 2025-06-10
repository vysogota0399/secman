package repositories

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
)

func TestNewSessions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockBarrier := server.NewMockIBarrier(ctrl)

	type args struct {
		lg *logging.ZapLogger
		b  server.IBarrier
	}
	tests := []struct {
		name string
		args args
		want *Sessions
	}{
		{
			name: "successful creation",
			args: args{
				lg: mockLogger,
				b:  mockBarrier,
			},
			want: &Sessions{
				lg: mockLogger,
				b:  mockBarrier,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewSessions(tt.args.lg, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewSessions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSessions_Get(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockBarrier := server.NewMockIBarrier(ctrl)

	// Setup test data
	testSession := Session{
		UUID:      "test-uuid",
		Sub:       "test-sub",
		ExpiredAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		Engine:    "test-engine",
	}
	sessionData, _ := json.Marshal(testSession)

	type fields struct {
		lg *logging.ZapLogger
		b  server.IBarrier
	}
	type args struct {
		ctx context.Context
		sid string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    Session
		wantErr bool
		prepare func(storage *server.MockIBarrier)
	}{
		{
			name: "successful get",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx: context.Background(),
				sid: "test-uuid",
			},
			want:    testSession,
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Get(gomock.Any(), "sys/sessions/test-uuid").
					Return(server.Entry{
						Key:   "sys/sessions/test-uuid",
						Value: string(sessionData),
					}, nil)
			},
		},
		{
			name: "not found",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx: context.Background(),
				sid: "non-existent",
			},
			want:    Session{},
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Get(gomock.Any(), "sys/sessions/non-existent").
					Return(server.Entry{}, server.ErrEntryNotFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Sessions{
				lg: tt.fields.lg,
				b:  tt.fields.b,
			}

			if tt.prepare != nil {
				tt.prepare(mockBarrier)
			}

			got, err := s.Get(tt.args.ctx, tt.args.sid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sessions.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Equal(t, got.UUID, tt.want.UUID)
		})
	}
}

func TestSessions_Create(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockBarrier := server.NewMockIBarrier(ctrl)

	type fields struct {
		lg *logging.ZapLogger
		b  server.IBarrier
	}
	type args struct {
		ctx  context.Context
		sess *Session
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(storage *server.MockIBarrier)
	}{
		{
			name: "successful create",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx: context.Background(),
				sess: &Session{
					UUID:      "test-uuid",
					Sub:       "test-sub",
					ExpiredAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
					Engine:    "test-engine",
				},
			},
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Update(gomock.Any(), "sys/sessions/test-uuid", gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "create with zero expiration",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx: context.Background(),
				sess: &Session{
					UUID:      "test-uuid-2",
					Sub:       "test-sub",
					ExpiredAt: time.Time{},
					CreatedAt: time.Now(),
					Engine:    "test-engine",
				},
			},
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Update(gomock.Any(), "sys/sessions/test-uuid-2", gomock.Any(), time.Duration(0)).
					Return(nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Sessions{
				lg: tt.fields.lg,
				b:  tt.fields.b,
			}

			if tt.prepare != nil {
				tt.prepare(mockBarrier)
			}

			if err := s.Create(tt.args.ctx, tt.args.sess); (err != nil) != tt.wantErr {
				t.Errorf("Sessions.Create() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
