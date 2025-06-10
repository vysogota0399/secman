package tokens

import (
	"context"
	"encoding/json"

	"github.com/vysogota0399/secman/internal/secman"
	"github.com/vysogota0399/secman/internal/secman/cryptoutils"
)

type Token struct {
	Value []byte `json:"value"`
	Key   string `json:"key"`
}

func (t *Token) init() error {
	t.Value = cryptoutils.GenerateRandom(32)
	return nil
}

type TokensRepository struct {
	storage secman.ILogicalStorage
}

func NewLogicalStorage(storage secman.BarrierStorage) secman.ILogicalStorage {
	return secman.NewLogicalStorage(storage, "sys/tokens")
}

func NewTokensRepository(barrier secman.BarrierStorage) *TokensRepository {
	return &TokensRepository{storage: NewLogicalStorage(barrier)}
}

func (r *TokensRepository) Find(ctx context.Context, key string) (Token, error) {
	entry, err := r.storage.Get(ctx, key)
	if err != nil {
		return Token{}, err
	}

	var token Token
	if err := json.Unmarshal([]byte(entry.Value), &token); err != nil {
		return Token{}, err
	}

	return token, nil
}

func (r *TokensRepository) Create(ctx context.Context, token Token) error {
	bts, err := json.Marshal(token)
	if err != nil {
		return err
	}

	return r.storage.Update(ctx, token.Key, secman.Entry{Value: string(bts), Key: token.Key}, 0)
}
