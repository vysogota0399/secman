package repositories

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	UUID      string    `json:"uuid"`
	Login     string    `json:"login"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
}

func (u User) Empty() bool {
	return u.UUID == "" && u.Login == "" && u.Password == "" && u.CreatedAt.IsZero()
}

func (u *User) HashPwd() error {
	const hashCost = 10
	pass, err := bcrypt.GenerateFromPassword([]byte(u.Password), hashCost)
	if err != nil {
		return err
	}

	u.Password = string(pass)
	return nil
}

type Users struct {
	lg *logging.ZapLogger
	b  secman.IBarrier
}

func NewUsers(lg *logging.ZapLogger, b secman.IBarrier) *Users {
	return &Users{lg: lg, b: b}
}

func (u *Users) Get(ctx context.Context, uuid string) (User, error) {
	data, err := u.b.Get(ctx, "sys/users/"+uuid)
	if err != nil {
		return User{}, err
	}

	var user User
	if err := json.Unmarshal([]byte(data.Value), &user); err != nil {
		return User{}, err
	}

	return user, nil
}

func (u *Users) Create(ctx context.Context, user *User) error {
	user.UUID = uuid.New().String()
	user.CreatedAt = time.Now()
	key := "sys/users/" + user.UUID

	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}

	entry := secman.Entry{
		Path:  key,
		Value: string(userJSON),
	}

	return u.b.Update(ctx, key, entry, 0)
}
