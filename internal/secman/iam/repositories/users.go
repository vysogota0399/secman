package repositories

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Login     string    `json:"login"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
	Path      string
}

func (u User) Empty() bool {
	return u.Login == "" && u.Password == "" && u.CreatedAt.IsZero()
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

func (u *Users) Get(ctx context.Context, login string) (User, error) {
	data, err := u.b.Get(ctx, "sys/users/"+login)
	if err != nil {
		return User{}, err
	}

	var user User
	if err := json.Unmarshal([]byte(data.Value), &user); err != nil {
		return User{}, err
	}

	user.Path = data.Path
	return user, nil
}

func (u *Users) GetOk(ctx context.Context, login string) (User, bool, error) {
	data, ok, err := u.b.GetOk(ctx, "sys/users/"+login)
	if err != nil {
		return User{}, false, err
	}

	if !ok {
		return User{}, false, nil
	}

	var user User
	if err := json.Unmarshal([]byte(data.Value), &user); err != nil {
		return User{}, false, err
	}

	return user, ok, nil
}

func (u *Users) Update(ctx context.Context, user *User) error {
	user.CreatedAt = time.Now()
	key := "sys/users/" + user.Login

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
