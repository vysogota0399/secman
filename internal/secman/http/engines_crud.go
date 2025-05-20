package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type EnginesCrud struct {
	core *secman.Core
}

func NewEnginesCrud(core *secman.Core) *EnginesCrud {
	return &EnginesCrud{core: core}
}

func (h *EnginesCrud) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		path := c.Param("path")
		backend, err := h.core.Router.Resolve(path)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "engine not found for specified path"})
			return
		}

		errMsg := gin.H{"error": "engine not found for specified path and method"}
		paths, ok := backend.Paths()[c.Request.Method]
		if !ok {
			c.JSON(http.StatusNotFound, errMsg)
			return
		}

		pathProcessor, ok := paths[path]
		if !ok {
			c.JSON(http.StatusNotFound, errMsg)
			return
		}

		if pathProcessor.Handler == nil {
			c.JSON(http.StatusNotImplemented, gin.H{"error": "path not implemented"})
			return
		}

		processHandler(c, h.core.Log, pathProcessor.Handler)
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
