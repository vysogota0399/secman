package logopass

import (
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/vysogota0399/secman/internal/server"
)

func NewTestBackend(t *testing.T) *Backend {
	lg := server.NewLogger(t)
	cnt := gomock.NewController(t)
	repo := NewMockParamsRepository(cnt)
	iam := NewMockIamAdapter(cnt)

	be := NewBackend(lg, &Logopass{iam: iam}, repo)

	return be
}
