package tokens

import (
	"context"
	"crypto/rand"
	"encoding/json"

	"github.com/vysogota0399/secman/internal/secman"
)

type Token struct {
	Value []byte `json:"value"`
	Path  string `json:"path"`
}

func (t *Token) init() error {
	rnd := rand.Reader

	token := make([]byte, 32)
	if _, err := rnd.Read(token); err != nil {
		return err
	}

	t.Value = token

	return nil
}

type TokensRepository struct {
	storage secman.IStorage
}

func NewTokensRepository(storage secman.IStorage) *TokensRepository {
	return &TokensRepository{storage: storage}
}

func (r *TokensRepository) Find(ctx context.Context, path string) (Token, error) {
	entry, err := r.storage.Get(ctx, path)
	if err != nil {
		return Token{}, err
	}

	var token Token
	if err := json.Unmarshal(entry.Value, &token); err != nil {
		return Token{}, err
	}

	return token, nil
}

func (r *TokensRepository) Create(ctx context.Context, token Token) error {
	bts, err := json.Marshal(token)
	if err != nil {
		return err
	}

	return r.storage.Update(ctx, token.Path, secman.PhysicalEntry{Value: bts}, 0)
}
