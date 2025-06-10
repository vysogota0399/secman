package logopass

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	logopass_repos "github.com/vysogota0399/secman/internal/secman/engines/logopass/repositories"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/iam"
	iam_repos "github.com/vysogota0399/secman/internal/secman/iam/repositories"
	"golang.org/x/crypto/bcrypt"
)

func TestNewLogopass(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIam := NewMockIamAdapter(ctrl)
	logger := secman.NewLogger(t)

	type args struct {
		iam IamAdapter
		lg  *logging.ZapLogger
	}
	tests := []struct {
		name string
		args args
		want *Logopass
	}{
		{
			name: "successful creation",
			args: args{
				iam: mockIam,
				lg:  logger,
			},
			want: &Logopass{
				iam: mockIam,
				lg:  logger,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewLogopass(tt.args.iam, tt.args.lg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewLogopass() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogopass_Login(t *testing.T) {
	ctrl := secman.NewController(t)
	mockIam := NewMockIamAdapter(ctrl)
	logger := secman.NewLogger(t)

	type fields struct {
		iam IamAdapter
		lg  *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		user    iam_repos.User
		backend *Backend
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
		setup   func()
	}{
		{
			name: "successful login",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx: context.Background(),
				user: iam_repos.User{
					Path: "/test/user",
				},
				backend: &Backend{
					params: &logopass_repos.Params{
						SecretKey: "test-secret",
						TokenTTL:  time.Hour * 24,
					},
				},
			},
			wantErr: false,
			setup: func() {
				mockIam.EXPECT().
					Login(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "login with default TTL",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx: context.Background(),
				user: iam_repos.User{
					Path: "/test/user",
				},
				backend: &Backend{
					params: &logopass_repos.Params{
						SecretKey: "test-secret",
					},
				},
			},
			wantErr: false,
			setup: func() {
				mockIam.EXPECT().
					Login(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "login failed",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx: context.Background(),
				user: iam_repos.User{
					Path: "/test/user",
				},
				backend: &Backend{
					params: &logopass_repos.Params{
						SecretKey: "test-secret",
						TokenTTL:  time.Hour * 24,
					},
				},
			},
			wantErr: true,
			setup: func() {
				mockIam.EXPECT().
					Login(gomock.Any(), gomock.Any()).
					Return(assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			lp := Logopass{
				iam: tt.fields.iam,
				lg:  tt.fields.lg,
			}
			got, err := lp.Login(tt.args.ctx, tt.args.user, tt.args.backend)
			if (err != nil) != tt.wantErr {
				t.Errorf("Logopass.Login() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got == "" {
				t.Error("Logopass.Login() returned empty token")
			}
		})
	}
}

func TestLogopass_Authorize(t *testing.T) {
	ctrl := secman.NewController(t)
	mockIam := NewMockIamAdapter(ctrl)
	logger := secman.NewLogger(t)

	type fields struct {
		lg *logging.ZapLogger
	}
	type args struct {
		ctx     context.Context
		token   string
		backend *Backend
	}
	tests := []struct {
		name    string
		fields  *fields
		args    args
		wantErr bool
		setup   func(args *args, lp *Logopass)
	}{
		{
			name: "successful authorization",
			fields: &fields{
				lg: logger,
			},
			args: args{
				ctx: context.Background(),
				backend: &Backend{
					params: &logopass_repos.Params{
						SecretKey: "test-secret",
					},
				},
			},
			wantErr: false,
			setup: func(args *args, lp *Logopass) {
				session := iam_repos.Session{
					UUID:      "test-uuid",
					Sub:       "/test/user",
					ExpiredAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
					Engine:    "logopass",
				}

				tkn, err := lp.buildJWTString(session, args.backend.params.SecretKey)
				if err != nil {
					t.Errorf("failed to build JWT string: %v", err)
				}

				args.token = tkn

				lp.iam.(*MockIamAdapter).EXPECT().
					Authorize(gomock.Any(), gomock.Any()).
					Return(session, nil)
			},
		},
		{
			name: "expired session",
			fields: &fields{
				lg: logger,
			},
			args: args{
				ctx: context.Background(),
				backend: &Backend{
					params: &logopass_repos.Params{
						SecretKey: "test-secret",
					},
				},
			},
			wantErr: true,
			setup: func(args *args, lp *Logopass) {
				session := iam_repos.Session{
					UUID:      "test-uuid",
					Sub:       "/test/user",
					ExpiredAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
					Engine:    "logopass",
				}

				tkn, err := lp.buildJWTString(session, args.backend.params.SecretKey)
				if err != nil {
					t.Errorf("failed to build JWT string: %v", err)
				}

				args.token = tkn

				session.ExpiredAt = time.Now().Add(-time.Hour)

				lp.iam.(*MockIamAdapter).EXPECT().
					Authorize(gomock.Any(), gomock.Any()).
					Return(session, nil)
			},
		},
		{
			name: "err authorize failed",
			fields: &fields{
				lg: logger,
			},
			args: args{
				ctx: context.Background(),
				backend: &Backend{
					params: &logopass_repos.Params{
						SecretKey: "test-secret",
					},
				},
			},
			wantErr: true,
			setup: func(args *args, lp *Logopass) {
				session := iam_repos.Session{
					UUID:      "test-uuid",
					Sub:       "/test/user",
					ExpiredAt: time.Now().Add(time.Hour),
					CreatedAt: time.Now(),
					Engine:    "logopass",
				}

				tkn, err := lp.buildJWTString(session, args.backend.params.SecretKey)
				if err != nil {
					t.Errorf("failed to build JWT string: %v", err)
				}

				args.token = tkn

				lp.iam.(*MockIamAdapter).EXPECT().
					Authorize(gomock.Any(), gomock.Any()).
					Return(iam_repos.Session{}, assert.AnError)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lp := Logopass{
				iam: mockIam,
				lg:  tt.fields.lg,
			}

			if tt.setup != nil {
				tt.setup(&tt.args, &lp)
			}

			if err := lp.Authorize(tt.args.ctx, tt.args.token, tt.args.backend); (err != nil) != tt.wantErr {
				t.Errorf("Logopass.Authorize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLogopass_Authenticate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockIam := NewMockIamAdapter(ctrl)
	logger := secman.NewLogger(t)

	// Generate a proper bcrypt hash for the test password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("failed to generate password hash: %v", err)
	}

	type fields struct {
		iam IamAdapter
		lg  *logging.ZapLogger
	}
	type args struct {
		ctx      context.Context
		login    string
		password string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    iam_repos.User
		wantErr bool
		setup   func()
	}{
		{
			name: "successful authentication",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx:      context.Background(),
				login:    "testuser",
				password: "testpass",
			},
			want: iam_repos.User{
				Login:    "testuser",
				Password: string(hashedPassword),
				Path:     "/test/user",
			},
			wantErr: false,
			setup: func() {
				mockIam.EXPECT().
					GetUser(gomock.Any(), "testuser").
					Return(iam_repos.User{
						Login:    "testuser",
						Password: string(hashedPassword),
						Path:     "/test/user",
					}, nil)
			},
		},
		{
			name: "user not found",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx:      context.Background(),
				login:    "nonexistent",
				password: "testpass",
			},
			want:    iam_repos.User{},
			wantErr: true,
			setup: func() {
				mockIam.EXPECT().
					GetUser(gomock.Any(), "nonexistent").
					Return(iam_repos.User{}, secman.ErrEntryNotFound)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			lp := Logopass{
				iam: tt.fields.iam,
				lg:  tt.fields.lg,
			}
			got, err := lp.Authenticate(tt.args.ctx, tt.args.login, tt.args.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("Logopass.Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Logopass.Authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLogopass_Register(t *testing.T) {
	ctrl := secman.NewController(t)
	mockIam := NewMockIamAdapter(ctrl)
	logger := secman.NewLogger(t)

	type fields struct {
		iam IamAdapter
		lg  *logging.ZapLogger
	}
	type args struct {
		ctx  context.Context
		user iam_repos.User
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
		setup   func()
	}{
		{
			name: "successful registration",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx: context.Background(),
				user: iam_repos.User{
					Login:    "newuser",
					Password: "testpass",
					Path:     "/test/user",
				},
			},
			wantErr: false,
			setup: func() {
				mockIam.EXPECT().
					Register(gomock.Any(), gomock.Any()).
					Return(nil)
			},
		},
		{
			name: "user already exists",
			fields: fields{
				iam: mockIam,
				lg:  logger,
			},
			args: args{
				ctx: context.Background(),
				user: iam_repos.User{
					Login:    "existinguser",
					Password: "testpass",
					Path:     "/test/user",
				},
			},
			wantErr: true,
			setup: func() {
				mockIam.EXPECT().
					Register(gomock.Any(), gomock.Any()).
					Return(iam.ErrUserAlreadyExists)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			lp := Logopass{
				iam: tt.fields.iam,
				lg:  tt.fields.lg,
			}
			if err := lp.Register(tt.args.ctx, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("Logopass.Register() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
