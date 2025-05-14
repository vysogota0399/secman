package http

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Enable struct {
	core *secman.Core
	log  *logging.ZapLogger
}

func NewEnable(core *secman.Core) *Enable {
	return &Enable{core: core, log: core.Log}
}

func (h *Enable) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		name := c.Param("engine")
		h.log.DebugCtx(c.Request.Context(), "enable start", zap.String("engine", name))

		engine, err := h.core.Router.Register(c.Request.Context(), name)
		if err != nil {
			if errors.Is(err, secman.ErrEngineNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "engine " + name + " not found"})
				return
			}

			if errors.Is(err, secman.ErrEngineAlreadyRegistered) {
				c.Status(http.StatusNotModified)
				return
			}

			h.log.ErrorCtx(c.Request.Context(), "enable failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "enable engine failed, see logs for more details"})
			return
		}

		resp, err := engine.Enable(c.Request.Context(), &secman.LogicalRequest{
			Context: c,
		})
		if err != nil {
			h.core.Router.Delete(name)
			h.log.ErrorCtx(c.Request.Context(), "enable failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "enable engine failed, see logs for more details"})
			return
		}

		c.JSON(resp.Status, gin.H{"message": resp.Message})
	}
}
