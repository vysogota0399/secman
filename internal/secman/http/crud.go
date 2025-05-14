package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Crud struct {
	core *secman.Core
}

func NewCrud(core *secman.Core) *Crud {
	return &Crud{core: core}
}

func (h *Crud) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		path := c.Param("path")
		backend, err := h.core.Router.Resolve(path)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "engine not found for specified path"})
			return
		}

		for _, p := range backend.Paths() {
			if p.Path == path && p.Method == c.Request.Method {
				processHandler(c, h.core.Log, p.Handler)
				return
			}
		}

		c.JSON(http.StatusNotFound, gin.H{"error": "path not found for specified path and method"})
	}
}

func processHandler(c *gin.Context, lg *logging.ZapLogger, h func(c *gin.Context) (*secman.LogicalResponse, error)) {
	resp, err := h(c)
	if err != nil {
		lg.ErrorCtx(c.Request.Context(), "error processing handler", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "request failed, see logs for more details"})
		return
	}

	c.JSON(resp.Status, resp.Message)
}
