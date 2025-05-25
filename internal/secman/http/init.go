package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/logging"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Init struct {
	core           *secman.Core
	log            *logging.ZapLogger
	coreRepository *secman.CoreRepository
}

func NewInit(
	core *secman.Core,
	coreRepository *secman.CoreRepository,
) *Init {
	return &Init{
		core:           core,
		log:            core.Log,
		coreRepository: coreRepository,
	}
}

func (h *Init) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		h.log.DebugCtx(c.Request.Context(), "init start")

		if h.core.IsInitialized.Load() {
			c.JSON(http.StatusOK, gin.H{"message": "already initialized"})
			return
		}

		if err := h.core.Init(h.coreRepository); err != nil {
			h.log.ErrorCtx(c.Request.Context(), "init core failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "init core failed, see logs for more details"})
			return
		}

		rootToken, err := h.core.RootTokens.Gen(c.Request.Context(), secman.RootTokenKey)
		if err != nil {
			h.log.ErrorCtx(c.Request.Context(), "init root token failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "init root token failed, see logs for more details"})
			return
		}

		unsealTokens, err := h.core.Barrier.Init(c.Request.Context())
		if err != nil {
			h.log.ErrorCtx(c.Request.Context(), "init barrier failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "init barrier failed, see logs for more details"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "initialized", "root_token": rootToken, "unseal_tokens": unsealTokens})
	}
}
