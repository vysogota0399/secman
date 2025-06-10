package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
	"go.uber.org/zap"
)

type Engine struct {
	core *server.Core
}

func NewEngine(core *server.Core) *Engine {
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

		router := backend.Router()
		if router == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "engine not found for specified path"})
			return
		}

		resp, err := router.Handle(c)
		if err != nil {
			h.core.Log.ErrorCtx(c.Request.Context(), "error processing handler", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "request failed, see logs for more details"})
			return
		}

		if resp.Reader != nil {
			defer resp.Reader.Close()
		}

		for k, v := range resp.Headers {
			c.Header(k, v)
		}

		if resp.Headers["Content-Type"] == "application/json" || resp.Headers["Content-Type"] == "" {
			c.JSON(resp.Status, resp.Message)
			return
		}

		if resp.Headers["Content-Type"] == "application/octet-stream" {
			c.DataFromReader(resp.Status, resp.ContentSize, resp.Headers["Content-Type"], resp.Reader, nil)
			return
		}

		c.Status(resp.Status)
	}
}
