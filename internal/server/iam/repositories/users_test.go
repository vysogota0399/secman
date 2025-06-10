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

func TestUser_Empty(t *testing.T) {
	type fields struct {
		Login     string
		Password  string
		CreatedAt time.Time
		Path      string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "empty user",
			fields: fields{
				Login:     "",
				Password:  "",
				CreatedAt: time.Time{},
				Path:      "",
			},
			want: true,
		},
		{
			name: "non-empty user",
			fields: fields{
				Login:     "test",
				Password:  "password",
				CreatedAt: time.Now(),
				Path:      "sys/users/test",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := User{
				Login:     tt.fields.Login,
				Password:  tt.fields.Password,
				CreatedAt: tt.fields.CreatedAt,
				Path:      tt.fields.Path,
			}
			if got := u.Empty(); got != tt.want {
				t.Errorf("User.Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUser_HashPwd(t *testing.T) {
	type fields struct {
		Login     string
		Password  string
		CreatedAt time.Time
		Path      string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid password",
			fields: fields{
				Login:     "test",
				Password:  "validPassword123",
				CreatedAt: time.Now(),
				Path:      "sys/users/test",
			},
			wantErr: false,
		},
		{
			name: "empty password",
			fields: fields{
				Login:     "test",
				Password:  "",
				CreatedAt: time.Now(),
				Path:      "sys/users/test",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{
				Login:     tt.fields.Login,
				Password:  tt.fields.Password,
				CreatedAt: tt.fields.CreatedAt,
				Path:      tt.fields.Path,
			}
			if err := u.HashPwd(); (err != nil) != tt.wantErr {
				t.Errorf("User.HashPwd() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && u.Password == tt.fields.Password {
				t.Error("User.HashPwd() password was not hashed")
			}
		})
	}
}

func TestNewUsers(t *testing.T) {
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
		want *Users
	}{
		{
			name: "create new users repository",
			args: args{
				lg: mockLogger,
				b:  mockBarrier,
			},
			want: &Users{
				lg: mockLogger,
				b:  mockBarrier,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewUsers(tt.args.lg, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewUsers() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUsers_Get(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockBarrier := server.NewMockIBarrier(ctrl)

	// Setup test data
	testUser := User{
		Login:     "testuser",
		Password:  "hashedpassword",
		CreatedAt: time.Now(),
	}
	userData, _ := json.Marshal(testUser)

	type fields struct {
		lg *logging.ZapLogger
		b  server.IBarrier
	}
	type args struct {
		ctx   context.Context
		login string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    User
		wantErr bool
		prepare func(storage *server.MockIBarrier)
	}{
		{
			name: "get existing user",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx:   context.Background(),
				login: "testuser",
			},
			want: func() User {
				u := testUser
				u.Path = "sys/users/testuser"
				return u
			}(),
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Get(gomock.Any(), "sys/users/testuser").
					Return(server.Entry{
						Key:   "sys/users/testuser",
						Value: string(userData),
					}, nil)
			},
		},
		{
			name: "get non-existing user",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx:   context.Background(),
				login: "nonexistent",
			},
			want:    User{},
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Get(gomock.Any(), "sys/users/nonexistent").
					Return(server.Entry{}, server.ErrEntryNotFound)
			},
		},
		{
			name: "get user with invalid json",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx:   context.Background(),
				login: "invalid",
			},
			want:    User{},
			wantErr: true,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Get(gomock.Any(), "sys/users/invalid").
					Return(server.Entry{
						Key:   "sys/users/invalid",
						Value: "invalid json",
					}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &Users{
				lg: tt.fields.lg,
				b:  tt.fields.b,
			}

			if tt.prepare != nil {
				tt.prepare(mockBarrier)
			}

			got, err := u.Get(tt.args.ctx, tt.args.login)
			if (err != nil) != tt.wantErr {
				t.Errorf("Users.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, got.Login, tt.want.Login)
		})
	}
}

func TestUsers_GetOk(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockBarrier := server.NewMockIBarrier(ctrl)

	// Setup test data
	testUser := User{
		Login:     "testuser",
		Password:  "hashedpassword",
		CreatedAt: time.Now(),
	}
	userData, _ := json.Marshal(testUser)

	type fields struct {
		lg *logging.ZapLogger
		b  server.IBarrier
	}
	type args struct {
		ctx   context.Context
		login string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    User
		want1   bool
		wantErr bool
		prepare func(storage *server.MockIBarrier)
	}{
		{
			name: "get existing user",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx:   context.Background(),
				login: "testuser",
			},
			want:    testUser,
			want1:   true,
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					GetOk(gomock.Any(), "sys/users/testuser").
					Return(server.Entry{
						Key:   "sys/users/testuser",
						Value: string(userData),
					}, true, nil)
			},
		},
		{
			name: "get non-existing user",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx:   context.Background(),
				login: "nonexistent",
			},
			want:    User{},
			want1:   false,
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					GetOk(gomock.Any(), "sys/users/nonexistent").
					Return(server.Entry{}, false, nil)
			},
		},
		{
			name: "get user with invalid json",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx:   context.Background(),
				login: "invalid",
			},
			want:    User{},
			want1:   false,
			wantErr: true,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					GetOk(gomock.Any(), "sys/users/invalid").
					Return(server.Entry{
						Key:   "sys/users/invalid",
						Value: "invalid json",
					}, true, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &Users{
				lg: tt.fields.lg,
				b:  tt.fields.b,
			}

			if tt.prepare != nil {
				tt.prepare(mockBarrier)
			}

			got, got1, err := u.GetOk(tt.args.ctx, tt.args.login)
			if (err != nil) != tt.wantErr {
				t.Errorf("Users.GetOk() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, got.Login, tt.want.Login)
			assert.Equal(t, got1, tt.want1)
		})
	}
}

func TestUsers_Update(t *testing.T) {
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
		user *User
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(storage *server.MockIBarrier)
	}{
		{
			name: "update existing user",
			fields: fields{
				lg: mockLogger,
				b:  mockBarrier,
			},
			args: args{
				ctx: context.Background(),
				user: &User{
					Login:     "testuser",
					Password:  "newpassword",
					CreatedAt: time.Now(),
				},
			},
			wantErr: false,
			prepare: func(storage *server.MockIBarrier) {
				storage.EXPECT().
					Update(gomock.Any(), "sys/users/testuser", gomock.Any(), time.Duration(0)).
					DoAndReturn(func(_ context.Context, key string, entry server.Entry, _ time.Duration) error {
						var user User
						if err := json.Unmarshal([]byte(entry.Value), &user); err != nil {
							return err
						}
						if user.Login != "testuser" {
							t.Errorf("Update() got user.Login = %v, want %v", user.Login, "testuser")
						}
						if user.Password != "newpassword" {
							t.Errorf("Update() got user.Password = %v, want %v", user.Password, "newpassword")
						}
						if user.Path != "" {
							t.Errorf("Update() got user.Path = %v, want %v", user.Path, "")
						}
						if user.CreatedAt.IsZero() {
							t.Error("Update() got zero CreatedAt")
						}
						return nil
					})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &Users{
				lg: tt.fields.lg,
				b:  tt.fields.b,
			}

			if tt.prepare != nil {
				tt.prepare(mockBarrier)
			}

			if err := u.Update(tt.args.ctx, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("Users.Update() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
