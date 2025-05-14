package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Init struct {
	core *secman.Core
	log  *logging.ZapLogger
}

func NewInit(core *secman.Core, enginesMap secman.EnginesMap) *Init {
	return &Init{core: core, log: core.Log}
}

func (h *Init) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		h.log.DebugCtx(c.Request.Context(), "init start")

		err := h.core.Init()
		if err != nil {
			h.log.ErrorCtx(c.Request.Context(), "init failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "init failed, see logs for more details"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "initialized"})
	}
}
