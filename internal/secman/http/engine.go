package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Engine struct {
	core *secman.Core
}

func NewEngine(core *secman.Core) *Engine {
	return &Engine{core: core}
}

func (h *Engine) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		path := c.Param("path")
		backend, err := h.core.Router.Resolve(path)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "engine not found for specified path"})
			return
		}

		resp, err := backend.Router().Handle(c)
		if err != nil {
			h.core.Log.ErrorCtx(c.Request.Context(), "error processing handler", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "request failed, see logs for more details"})
			return
		}

		c.JSON(resp.Status, resp.Message)
	}
}
