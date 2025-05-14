package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Post struct {
	core *secman.Core
}

func NewPost(core *secman.Core) *Post {
	return &Post{core: core}
}

func (h *Post) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
	}
}

type Get struct {
	core *secman.Core
}

func NewGet(core *secman.Core) *Get {
	return &Get{core: core}
}

func (h *Get) Handler() func(c *gin.Context) {
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

type Put struct {
	core *secman.Core
}

func NewPut(core *secman.Core) *Put {
	return &Put{core: core}
}

func (h *Put) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
	}
}

type Delete struct {
	core *secman.Core
}

func NewDelete(core *secman.Core) *Delete {
	return &Delete{core: core}
}

func (h *Delete) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
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
