package cli

import "errors"

type LogopassAuthProvider struct {
	tokenPath string
}

func NewLogopassAuthProvider() *LogopassAuthProvider {
	return &LogopassAuthProvider{
		tokenPath: "engine/auth/logopass/login/token",
	}
}

var _ AuthProvider = (*LogopassAuthProvider)(nil)

func (a *LogopassAuthProvider) Authenticate(h map[string]string, session ISession) error {
	token, ok := session.Get(a.tokenPath)
	if !ok || token == "" {
		return errors.New("no token found")
	}

	h["Authorization"] = "Bearer " + token
	return nil
}

func (a *LogopassAuthProvider) Login(session ISession, token string) {
	session.Set(a.tokenPath, token)
}

func (a *LogopassAuthProvider) GetToken(session ISession) (string, bool) {
	t, ok := session.Get(a.tokenPath)
	return t, ok
}

type RootTokenAuthProvider struct {
	tokenPath string
}

func NewRootTokenAuthProvider() *RootTokenAuthProvider {
	return &RootTokenAuthProvider{
		tokenPath: "root_token",
	}
}

var _ AuthProvider = (*RootTokenAuthProvider)(nil)

func (a *RootTokenAuthProvider) Authenticate(h map[string]string, session ISession) error {
	token, ok := session.Get(a.tokenPath)
	if !ok || token == "" {
		return errors.New("no token found")
	}

	h["X-Secman-Token"] = token
	return nil
}

func (a *RootTokenAuthProvider) Login(session ISession, token string) {
	session.Set(a.tokenPath, token)
}

func (a *RootTokenAuthProvider) GetToken(session ISession) (string, bool) {
	t, ok := session.Get(a.tokenPath)
	return t, ok
}
