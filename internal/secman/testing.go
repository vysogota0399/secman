package secman

import (
	"testing"

	"github.com/golang/mock/gomock"
)

func NewController(t *testing.T) *gomock.Controller {
	ctrl := gomock.NewController(t)

	t.Cleanup(func() {
		ctrl.Finish()
	})

	return ctrl
}
