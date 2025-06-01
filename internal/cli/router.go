package cli

import (
	"errors"
	"fmt"

	"github.com/armon/go-radix"
	"github.com/vysogota0399/secman/internal/secman"
)

type LogicalRouter struct {
	engines *radix.Tree
}

func NewLogicalRouter(engines ...secman.LogicalBackend) *LogicalRouter {
	tree := radix.New()

	for _, engine := range engines {
		tree.Insert(engine.RootPath(), engine)
	}

	r := &LogicalRouter{
		engines: tree,
	}

	return r
}

type LogicalOperation struct {
	Name string
	Args []Arg
}

type Arg struct {
	Name  string
	Usage string
	Type  string
}

var (
	ErrEngineNotFound = errors.New("engine not found")
)

func (r *LogicalRouter) Resolve(path string) (secman.LogicalBackend, error) {
	_, engine, ok := r.engines.LongestPrefix(path)
	if !ok {
		return nil, fmt.Errorf("router: path %s: %w", path, ErrEngineNotFound)
	}

	be, ok := engine.(secman.LogicalBackend)
	if !ok {
		return nil, fmt.Errorf("type cast to backend failed for engine %s %T", path, engine)
	}

	return be, nil
}
