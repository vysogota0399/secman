package secman

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/vysogota0399/secman/internal/logging"
)

type CoreRepository struct {
	storage IStorage
	log     *logging.ZapLogger
}

var coreParamsPath = "sys/core/params"

func NewCoreRepository(storage IStorage, log *logging.ZapLogger) *CoreRepository {
	return &CoreRepository{storage: storage, log: log}
}

type CoreParamsEntry struct {
	Initialized bool `json:"initialized"`
}

func (r *CoreRepository) IsCoreInitialized(ctx context.Context) (bool, error) {
	coreParams, err := r.entry(ctx)
	if err != nil {
		return false, err
	}

	return coreParams.Initialized, nil
}

func (r *CoreRepository) SetCoreInitialized(ctx context.Context, initialized bool) error {
	coreParams, err := r.entry(ctx)
	if err != nil {
		return err
	}

	coreParams.Initialized = initialized
	if err := r.updateEntry(ctx, coreParams); err != nil {
		return fmt.Errorf("core repository: failed to set initialized: %w", err)
	}

	return nil
}

func (r *CoreRepository) entry(ctx context.Context) (CoreParamsEntry, error) {
	var coreParams CoreParamsEntry
	core, err := r.storage.Get(ctx, coreParamsPath)
	if err != nil {
		return CoreParamsEntry{}, err
	}

	if core.Value == nil {
		return CoreParamsEntry{}, nil
	}

	err = json.Unmarshal(core.Value, &coreParams)
	if err != nil {
		return CoreParamsEntry{}, fmt.Errorf("core repository: failed to unmarshal core params %s: %w", string(core.Value), err)
	}

	return coreParams, nil
}

func (r *CoreRepository) updateEntry(ctx context.Context, entry CoreParamsEntry) error {
	value, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("core repository: failed to marshal core params %s: %w", string(value), err)
	}

	return r.storage.Update(ctx, coreParamsPath, PhysicalEntry{Value: value}, 0)
}

// IsEngineExist checks if the engine exists in the storage.
// If engine stored in the storage, it means that the engine was enabled.
func (r *CoreRepository) IsEngineExist(ctx context.Context, searchPath string) (bool, error) {
	entry, err := r.storage.Get(ctx, searchPath)
	if err != nil {
		return false, err
	}

	return entry.Value != nil, nil
}
