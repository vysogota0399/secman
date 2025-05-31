package client

type Session struct {
	Token   string
	Secrets map[string]string
}

func NewSession() *Session {
	return &Session{}
}

func (s *Session) Init() error {
	return nil
}

func (s *Session) Persist() error {
	return nil
}
