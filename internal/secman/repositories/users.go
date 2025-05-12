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
	UUID      string    `json:"uuid"`
	Login     string    `json:"login"`
	Password  string    `json:"password"`
	CreatedAt time.Time `json:"created_at"`
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
	lg      *logging.ZapLogger
	storage secman.IStorage
}

func NewUsers(lg *logging.ZapLogger, storage secman.IStorage) *Users {
	return &Users{lg: lg, storage: storage}
}

func (u *Users) Get(ctx context.Context, uuid string) (User, error) {
	data, err := u.storage.Get(ctx, "sys/users/"+uuid)
	if err != nil {
		return User{}, err
	}

	var user User
	if err := json.Unmarshal(data.Value, &user); err != nil {
		return User{}, err
	}

	return user, nil
}
