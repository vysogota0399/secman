package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Init struct {
	core    *secman.Core
	log     *logging.ZapLogger
	engines []secman.LogicalEngine
}

func NewInit(
	engines []secman.LogicalEngine,
	core *secman.Core,
) *Init {
	return &Init{
		core:    core,
		log:     core.Log,
		engines: engines,
	}
}

func (h *Init) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		h.log.DebugCtx(c.Request.Context(), "init start")

		// if h.core.IsInitialized() {
		// 	c.JSON(http.StatusOK, gin.H{"message": "already initialized"})
		// 	return
		// }

		em := make(map[string]secman.LogicalBackend)

		if len(h.engines) == 0 {
			h.log.ErrorCtx(c.Request.Context(), "engines map: no engines provided")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "engines map: no engines provided"})
			return
		}

		for _, engine := range h.engines {
			em[engine.Name()] = engine.Factory()
		}

		if err := h.core.Init(em); err != nil {
			h.log.ErrorCtx(c.Request.Context(), "init core failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "init core failed, see logs for more details"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "initialized"})
	}
}
