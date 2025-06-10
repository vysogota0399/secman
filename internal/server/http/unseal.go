package http

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
	"go.uber.org/zap"
)

type Unseal struct {
	core *server.Core
}

func NewUnseal(core *server.Core) *Unseal {
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

		decodedKey, err := base64.StdEncoding.DecodeString(req.Key)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid key"})
			return
		}

		if err := h.core.Unseal(c, decodedKey); err != nil {
			h.core.Log.ErrorCtx(c, "unseal failed", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "unseal failed, see logs for more details"})
			return
		}

		c.Status(http.StatusOK)
	}
}
