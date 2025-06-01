package cli

import (
	"context"
	"encoding/gob"
	"fmt"
	"os"
	"path"

	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap"
)

type Session struct {
	Token       string
	Secrets     map[string]string
	lg          *logging.ZapLogger
	storagePath string
}

var _ ISession = (*Session)(nil)

func NewSession(cfg *Config, lg *logging.ZapLogger) (*Session, error) {
	hd, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	s := &Session{
		Token:       cfg.RootToken,
		Secrets:     make(map[string]string),
		lg:          lg,
		storagePath: path.Join(hd, ".secman"),
	}

	return s, nil
}

func (s *Session) Init(ctx context.Context) error {
	var storage *os.File
	if _, err := os.Stat(s.storagePath); os.IsNotExist(err) {
		storage, err = os.OpenFile(s.storagePath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("failed to create storage file: %w", err)
		}
		defer storage.Close()

		enc := gob.NewEncoder(storage)
		if err := enc.Encode(s); err != nil {
			return fmt.Errorf("failed to encode session: %w", err)
		}
	} else {
		storage, err = os.OpenFile(s.storagePath, os.O_RDWR, 0600)
		if err != nil {
			return fmt.Errorf("failed to open storage file: %w", err)
		}
		defer storage.Close()

		dec := gob.NewDecoder(storage)
		if err := dec.Decode(s); err != nil {
			return fmt.Errorf("failed to decode session: %w", err)
		}
	}

	s.lg.DebugCtx(ctx, "session initialized", zap.Any("session", s))
	return nil
}

func (s *Session) Persist() error {
	storage, err := os.OpenFile(s.storagePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open storage file: %w", err)
	}
	defer storage.Close()

	enc := gob.NewEncoder(storage)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("failed to encode session: %w", err)
	}

	return nil
}

func (s *Session) GetToken() string {
	return s.Token
}

func (s *Session) SetRootToken(token string) {
	s.Token = token
}

func (s *Session) GetSecrets() map[string]string {
	return s.Secrets
}

func (s *Session) Set(key, value string) {
	s.Secrets[key] = value
}

func (s *Session) Get(key string) string {
	return s.Secrets[key]
}

const LogopassTokenKey = "engine/auth/logopass/login/token"

func (s *Session) Authenticate(h map[string]string) error {
	if token, ok := s.Secrets[LogopassTokenKey]; ok {
		h["Authorization"] = "Bearer " + token
		return nil
	}

	if s.Token != "" {
		h["X-Secman-Token"] = s.Token
		return nil
	}

	return nil
}

func (s *Session) TruncateSecrets() {
	s.Secrets = make(map[string]string)
}
