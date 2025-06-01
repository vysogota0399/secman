package http

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type EnableEngine struct {
	core   *secman.Core
	router secman.ILogicalRouter
	log    *logging.ZapLogger
}

func NewEnableEngine(core *secman.Core) *EnableEngine {
	return &EnableEngine{core: core, log: core.Log, router: core.Router}
}

func (h *EnableEngine) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		enginePath := c.Param("engine_path")

		be, err := h.router.Resolve(enginePath)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "engine " + enginePath + " not found"})
			return
		}

		resp, err := h.router.EnableEngine(c.Request.Context(), be, &secman.LogicalRequest{Context: c})
		if err != nil {
			if errors.Is(err, secman.ErrEngineNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "engine " + enginePath + " not found"})
				return
			}

			h.log.ErrorCtx(c.Request.Context(), "enable engine", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error, for more details see logs"})
			return
		}

		c.JSON(resp.Status, resp.Message)
	}
}
