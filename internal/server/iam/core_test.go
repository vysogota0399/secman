package iam

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server/iam/repositories"
)

func TestNewCore(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockSessRep := NewMockSessionsRepository(ctrl)
	mockUsersRep := NewMockUsersRepository(ctrl)

	type args struct {
		lg       *logging.ZapLogger
		sessRep  SessionsRepository
		usersRep UsersRepository
	}
	tests := []struct {
		name string
		args args
		want *Core
	}{
		{
			name: "successful creation",
			args: args{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			want: &Core{
				lg:            mockLogger,
				sessRep:       mockSessRep,
				usersRep:      mockUsersRep,
				registrateMtx: sync.Mutex{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewCore(tt.args.lg, tt.args.sessRep, tt.args.usersRep)
			assert.Equal(t, tt.want.lg, got.lg)
			assert.Equal(t, tt.want.sessRep, got.sessRep)
			assert.Equal(t, tt.want.usersRep, got.usersRep)
		})
	}
}

func TestCore_Authorize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockSessRep := NewMockSessionsRepository(ctrl)
	mockUsersRep := NewMockUsersRepository(ctrl)

	// Setup test data
	testSession := repositories.Session{
		UUID:      "test-uuid",
		Sub:       "test-sub",
		ExpiredAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		Engine:    "test-engine",
	}

	type fields struct {
		lg       *logging.ZapLogger
		sessRep  SessionsRepository
		usersRep UsersRepository
	}
	type args struct {
		ctx context.Context
		sid string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    repositories.Session
		wantErr bool
		prepare func(mockSessRep *MockSessionsRepository)
	}{
		{
			name: "successful authorization",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx: context.Background(),
				sid: "test-uuid",
			},
			want:    testSession,
			wantErr: false,
			prepare: func(mockSessRep *MockSessionsRepository) {
				mockSessRep.EXPECT().
					Get(gomock.Any(), "test-uuid").
					Return(testSession, nil)
			},
		},
		{
			name: "non-existent session",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx: context.Background(),
				sid: "non-existent",
			},
			want:    repositories.Session{},
			wantErr: false,
			prepare: func(mockSessRep *MockSessionsRepository) {
				mockSessRep.EXPECT().
					Get(gomock.Any(), "non-existent").
					Return(repositories.Session{}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Core{
				lg:       tt.fields.lg,
				sessRep:  tt.fields.sessRep,
				usersRep: tt.fields.usersRep,
			}

			if tt.prepare != nil {
				tt.prepare(mockSessRep)
			}

			got, err := c.Authorize(tt.args.ctx, tt.args.sid)
			if (err != nil) != tt.wantErr {
				t.Errorf("Core.Authorize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Core.Authorize() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCore_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockSessRep := NewMockSessionsRepository(ctrl)
	mockUsersRep := NewMockUsersRepository(ctrl)

	testSession := repositories.Session{
		UUID:      "test-uuid",
		Sub:       "test-sub",
		ExpiredAt: time.Now().Add(time.Hour),
		CreatedAt: time.Now(),
		Engine:    "test-engine",
	}

	type fields struct {
		lg       *logging.ZapLogger
		sessRep  SessionsRepository
		usersRep UsersRepository
	}
	type args struct {
		ctx     context.Context
		session repositories.Session
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(mockSessRep *MockSessionsRepository)
	}{
		{
			name: "successful login",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx:     context.Background(),
				session: testSession,
			},
			wantErr: false,
			prepare: func(mockSessRep *MockSessionsRepository) {
				mockSessRep.EXPECT().
					Create(gomock.Any(), &testSession).
					Return(nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Core{
				lg:       tt.fields.lg,
				sessRep:  tt.fields.sessRep,
				usersRep: tt.fields.usersRep,
			}

			if tt.prepare != nil {
				tt.prepare(mockSessRep)
			}

			if err := c.Login(tt.args.ctx, tt.args.session); (err != nil) != tt.wantErr {
				t.Errorf("Core.Login() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCore_Register(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockSessRep := NewMockSessionsRepository(ctrl)
	mockUsersRep := NewMockUsersRepository(ctrl)

	testUser := repositories.User{
		Login:    "testuser",
		Password: "testpass",
	}

	type fields struct {
		lg       *logging.ZapLogger
		sessRep  SessionsRepository
		usersRep UsersRepository
	}
	type args struct {
		ctx  context.Context
		user repositories.User
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		prepare func(mockUsersRep *MockUsersRepository)
	}{
		{
			name: "successful registration",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx:  context.Background(),
				user: testUser,
			},
			wantErr: false,
			prepare: func(mockUsersRep *MockUsersRepository) {
				mockUsersRep.EXPECT().
					GetOk(gomock.Any(), "testuser").
					Return(repositories.User{}, false, nil)
				mockUsersRep.EXPECT().
					Update(gomock.Any(), gomock.Any()).
					DoAndReturn(func(_ context.Context, user *repositories.User) error {
						if user.Login != "testuser" {
							t.Errorf("Register() got user.Login = %v, want %v", user.Login, "testuser")
						}
						if user.Password == "testpass" {
							t.Error("Register() password was not hashed")
						}
						if user.CreatedAt.IsZero() {
							t.Error("Register() got zero CreatedAt")
						}
						return nil
					})
			},
		},
		{
			name: "user already exists",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx:  context.Background(),
				user: testUser,
			},
			wantErr: true,
			prepare: func(mockUsersRep *MockUsersRepository) {
				mockUsersRep.EXPECT().
					GetOk(gomock.Any(), "testuser").
					Return(repositories.User{Login: "testuser"}, true, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Core{
				lg:       tt.fields.lg,
				sessRep:  tt.fields.sessRep,
				usersRep: tt.fields.usersRep,
			}

			if tt.prepare != nil {
				tt.prepare(mockUsersRep)
			}

			if err := c.Register(tt.args.ctx, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("Core.Register() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCore_GetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockLogger := &logging.ZapLogger{}
	mockSessRep := NewMockSessionsRepository(ctrl)
	mockUsersRep := NewMockUsersRepository(ctrl)

	// Setup test data
	testUser := repositories.User{
		Login:     "testuser",
		Password:  "hashedpassword",
		CreatedAt: time.Now(),
	}

	type fields struct {
		lg       *logging.ZapLogger
		sessRep  SessionsRepository
		usersRep UsersRepository
	}
	type args struct {
		ctx   context.Context
		login string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    repositories.User
		wantErr bool
		prepare func(mockUsersRep *MockUsersRepository)
	}{
		{
			name: "get existing user",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx:   context.Background(),
				login: "testuser",
			},
			want:    testUser,
			wantErr: false,
			prepare: func(mockUsersRep *MockUsersRepository) {
				mockUsersRep.EXPECT().
					Get(gomock.Any(), "testuser").
					Return(testUser, nil)
			},
		},
		{
			name: "get non-existent user",
			fields: fields{
				lg:       mockLogger,
				sessRep:  mockSessRep,
				usersRep: mockUsersRep,
			},
			args: args{
				ctx:   context.Background(),
				login: "nonexistent",
			},
			want:    repositories.User{},
			wantErr: false,
			prepare: func(mockUsersRep *MockUsersRepository) {
				mockUsersRep.EXPECT().
					Get(gomock.Any(), "nonexistent").
					Return(repositories.User{}, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Core{
				lg:       tt.fields.lg,
				sessRep:  tt.fields.sessRep,
				usersRep: tt.fields.usersRep,
			}

			if tt.prepare != nil {
				tt.prepare(mockUsersRep)
			}

			got, err := c.GetUser(tt.args.ctx, tt.args.login)
			if (err != nil) != tt.wantErr {
				t.Errorf("Core.GetUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Core.GetUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
