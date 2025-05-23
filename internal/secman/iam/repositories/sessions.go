package repositories

import (
	"context"
	"encoding/json"
	"errors"
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
	Engine    string    `json:"engine"`
}

type Sessions struct {
	lg *logging.ZapLogger
	b  secman.IBarrier
}

func NewSessions(lg *logging.ZapLogger, b secman.IBarrier) *Sessions {
	return &Sessions{lg: lg, b: b}
}

func (s *Sessions) Get(ctx context.Context, sid string) (Session, error) {
	data, err := s.b.Get(ctx, "sys/sessions/"+sid)
	if err != nil {
		if errors.Is(err, secman.ErrEntryNotFound) {
			return Session{}, nil
		}

		return Session{}, err
	}

	var sess Session

	if err := json.Unmarshal([]byte(data.Value), &sess); err != nil {
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
		Key:   "sys/sessions/" + sess.UUID,
		Value: string(session),
	}

	var ttl time.Duration
	if sess.ExpiredAt.IsZero() {
		ttl = 0
	} else {
		ttl = time.Until(sess.ExpiredAt)
	}

	if err := s.b.Update(ctx, "sys/sessions/"+sess.UUID, entry, ttl); err != nil {
		return err
	}

	return nil
}
