package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

type Status struct {
	core *secman.Core
}

func NewStatus(core *secman.Core) *Status {
	return &Status{core: core}
}

func (h *Status) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		status := map[string]any{
			"sealed":      h.core.IsSealed(),
			"initialized": h.core.IsInitialized(),
		}

		c.JSON(http.StatusOK, status)
	}
}
