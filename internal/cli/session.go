package cli

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap"
)

type AuthProvider interface {
	Authenticate(h map[string]string, session ISession) error
	Login(session ISession, token string)
	GetToken(session ISession) (string, bool)
}

type Session struct {
	Secrets      map[string]string
	lg           *logging.ZapLogger
	storagePath  string
	AuthProvider string
	providers    map[string]AuthProvider
}

var _ ISession = (*Session)(nil)

func NewSession(cfg *Config, lg *logging.ZapLogger) (*Session, error) {
	hd, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}

	s := &Session{
		Secrets:     make(map[string]string),
		lg:          lg,
		storagePath: path.Join(hd, ".secman"),
		providers: map[string]AuthProvider{
			"root_token": NewRootTokenAuthProvider(),
			"logopass":   NewLogopassAuthProvider(),
		},
	}

	if cfg.RootToken != "" {
		s.AuthProvider = "root_token"
		s.providers["root_token"].Login(s, cfg.RootToken)
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

func (s *Session) GetSecrets() map[string]string {
	return s.Secrets
}

func (s *Session) Set(key, value string) {
	s.Secrets[key] = value
}

func (s *Session) Get(key string) (string, bool) {
	value, ok := s.Secrets[key]
	return value, ok
}

func (s *Session) Authenticate(h map[string]string) error {
	provider, ok := s.providers[s.AuthProvider]
	if !ok {
		return errors.New("can't authenticate request, no auth provider selected")
	}

	if err := provider.Authenticate(h, s); err != nil {
		return err
	}

	return nil
}

func (s *Session) Login(token string, provider string) {
	s.AuthProvider = provider
	s.providers[provider].Login(s, token)
}

func (s *Session) Clear() {
	s.Secrets = make(map[string]string)
}

func (s *Session) GetAuthProvider(ap string) AuthProvider {
	return s.providers[ap]
}
