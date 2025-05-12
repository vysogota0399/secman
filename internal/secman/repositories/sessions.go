package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type Session struct {
	UUID      string    `json:"uuid"`
	Sub       string    `json:"sub"`
	ExpiredAt time.Time `json:"expired_at"`
	CreatedAt time.Time `json:"created_at"`
}

type Sessions struct {
	lg      *logging.ZapLogger
	storage secman.IBarrier
}

func NewSessions(lg *logging.ZapLogger, storage secman.IBarrier) *Sessions {
	return &Sessions{lg: lg, storage: storage}
}

func (s *Sessions) Get(ctx context.Context, sid string) (Session, error) {
	data, err := s.storage.Get(ctx, "sys/sessions/"+sid)
	if err != nil {
		return Session{}, err
	}

	var sess Session

	if err := json.Unmarshal(data.Value, &sess); err != nil {
		return Session{}, err
	}

	return sess, nil
}

func (s *Sessions) Create(ctx context.Context, sess *Session) error {
	session, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("sessions: create session marshal session: %w", err)
	}

	entry := secman.Entry{
		Path:  []byte("sys/sessions/" + sess.UUID),
		Value: session,
	}

	if err := s.storage.Update(ctx, "sys/sessions/"+sess.UUID, entry); err != nil {
		return err
	}

	return nil
}
