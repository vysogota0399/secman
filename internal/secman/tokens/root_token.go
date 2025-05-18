package tokens

import (
	"context"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type RootToken struct {
	tokensRepository *TokensRepository
}

func NewRootToken(tokensRepository *TokensRepository) *RootToken {
	return &RootToken{tokensRepository: tokensRepository}
}

func (rt *RootToken) Gen(ctx context.Context, path string) (string, error) {
	token := Token{}
	if err := token.init(); err != nil {
		return "", err
	}

	token.Path = path
	plainToken := token.Value

	const hashCost = 10
	hash, err := bcrypt.GenerateFromPassword([]byte(plainToken), hashCost)
	if err != nil {
		return "", err
	}

	token.Value = hash

	if err := rt.tokensRepository.Create(ctx, token); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(plainToken), nil
}

func (rt *RootToken) Compare(ctx context.Context, path string, token string) error {
	plainToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("root_token: decode token error %w", err)
	}

	hash, err := rt.tokensRepository.Find(ctx, path)
	if err != nil {
		return fmt.Errorf("root_token: token not found for path %s error: %w", path, err)
	}

	return bcrypt.CompareHashAndPassword(hash.Value, plainToken)
}
