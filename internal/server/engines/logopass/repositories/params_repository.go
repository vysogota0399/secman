package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/server"
)

type Params struct {
	TokenTTL  time.Duration `json:"token_ttl"`
	SecretKey string        `json:"secret_key"`
}

type ParamsRepository struct {
	lg      *logging.ZapLogger
	storage server.ILogicalStorage
}

func NewParamsRepository(b server.BarrierStorage, lg *logging.ZapLogger) *ParamsRepository {
	return &ParamsRepository{
		lg:      lg,
		storage: server.NewLogicalStorage(b, "auth/logopass"),
	}
}

func (r *ParamsRepository) IsExist(ctx context.Context) (bool, error) {
	_, ok, err := r.storage.GetOk(ctx, "")
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (r *ParamsRepository) Get(ctx context.Context) (*Params, error) {
	entry, err := r.storage.Get(ctx, "")
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

	entry := server.Entry{
		Value: string(entryValue),
	}

	return r.storage.Update(ctx, "", entry, 0)
}
