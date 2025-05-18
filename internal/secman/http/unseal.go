package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
	"go.uber.org/zap"
)

type Unseal struct {
	core *secman.Core
}

func NewUnseal(core *secman.Core) *Unseal {
	return &Unseal{core: core}
}

type UnsealRequest struct {
	Key string `json:"key" form:"key" binding:"required"`
}

func (h *Unseal) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		if !h.core.IsSealed.Load() {
			c.AbortWithStatus(http.StatusNotModified)
			return
		}

		var req UnsealRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "key is missing"})
			return
		}

		if err := h.core.Unseal(c, []byte(req.Key)); err != nil {
			h.core.Log.ErrorCtx(c, "unseal failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unseal failed, see logs for more details"})
			return
		}

		c.Status(http.StatusOK)
	}
}
