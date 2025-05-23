package secman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
)

type CoreRepository struct {
	storage BarrierStorage
	log     *logging.ZapLogger
}

func NewCoreRepository(storage BarrierStorage, log *logging.ZapLogger) *CoreRepository {
	return &CoreRepository{storage: storage, log: log}
}

type CoreEntry struct {
	Initialized bool `json:"initialized"`
}

func (r *CoreRepository) IsCoreInitialized(ctx context.Context) (bool, error) {
	coreParams, err := r.entry(ctx)
	if err != nil {
		if errors.Is(err, ErrEntryNotFound) {
			return false, nil
		}

		return false, err
	}

	return coreParams.Initialized, nil
}

func (r *CoreRepository) SetCoreInitialized(ctx context.Context, initialized bool) error {
	coreParams, err := r.entry(ctx)
	if err != nil && !errors.Is(err, ErrEntryNotFound) {
		return err
	}

	coreParams.Initialized = initialized
	if err := r.updateEntry(ctx, coreParams); err != nil {
		return fmt.Errorf("core repository: failed to set initialized: %w", err)
	}

	return nil
}

func (r *CoreRepository) entry(ctx context.Context) (CoreEntry, error) {
	var coreParams CoreEntry
	core, err := r.storage.Get(ctx, coreParamsPath)

	if err != nil {
		return CoreEntry{}, err
	}

	err = json.Unmarshal([]byte(core.Value), &coreParams)
	if err != nil {
		return CoreEntry{}, fmt.Errorf("core repository: failed to unmarshal core params %s: %w", core.Value, err)
	}

	return coreParams, nil
}

func (r *CoreRepository) updateEntry(ctx context.Context, entry CoreEntry) error {
	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("core repository: failed to marshal core params %s: %w", string(value), err)
	}

	return r.storage.Update(ctx, coreParamsPath, Entry{Value: string(value)}, 0)
}

// IsEngineExist checks if the engine exists in the storage.
// If engine stored in the storage, it means that the engine was enabled.
func (r *CoreRepository) IsEngineExist(ctx context.Context, searchPath string) (bool, error) {
	_, err := r.storage.Get(ctx, searchPath)
	if err != nil {
		if errors.Is(err, ErrEntryNotFound) {
			return false, nil
		}

		return false, err
	}

	return true, nil
}

type CoreConfig struct {
	Auth *Auth `json:"auth"`
}

func (r *CoreRepository) GetCoreAuthConfig(ctx context.Context) (*Auth, error) {
	entry, err := r.storage.Get(ctx, coreAuthPath)
	if err != nil {
		return nil, err
	}

	var authConfig Auth
	err = json.Unmarshal([]byte(entry.Value), &authConfig)
	if err != nil {
		return nil, fmt.Errorf("core repository: failed to unmarshal core config %s: %w", string(entry.Value), err)
	}

	return &authConfig, nil
}

func (r *CoreRepository) UpdateCoreAuthConfig(ctx context.Context, authConfig *Auth) error {
	value, err := json.Marshal(authConfig)
	if err != nil {
		return fmt.Errorf("core repository: failed to marshal core config %s: %w", string(value), err)
	}

	return r.storage.Update(ctx, coreAuthPath, Entry{Value: string(value)}, 0)
}
