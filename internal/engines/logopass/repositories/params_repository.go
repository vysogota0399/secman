package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
)

type Params struct {
	TokenTTL  time.Duration `json:"token_ttl"`
	SecretKey string        `json:"secret_key"`
}

type ParamsRepository struct {
	lg   *logging.ZapLogger
	b    secman.IBarrier
	path string
}

func NewParamsRepository(lg *logging.ZapLogger, b secman.IBarrier, basePath string) *ParamsRepository {
	return &ParamsRepository{lg: lg, b: b, path: strings.TrimPrefix(basePath, "/")}
}

func (r *ParamsRepository) IsExist(ctx context.Context) (bool, error) {
	_, ok, err := r.b.GetOk(ctx, r.path)
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (r *ParamsRepository) Get(ctx context.Context) (*Params, error) {
	entry, err := r.b.Get(ctx, r.path)
	if err != nil {
		return nil, err
	}

	params := &Params{}
	if err := json.Unmarshal([]byte(entry.Value), params); err != nil {
		return nil, err
	}

	return params, nil
}

func (r *ParamsRepository) Update(ctx context.Context, params *Params) error {
	entryValue, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("logopass: enable failed error when marshalling params %w", err)
	}

	entry := secman.Entry{
		Value: string(entryValue),
		Path:  r.path,
	}

	return r.b.Update(ctx, r.path, entry, 0)
}
