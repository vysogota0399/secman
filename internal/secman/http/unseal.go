package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

type Unseal struct {
	core *secman.Core
}

func NewUnseal(core *secman.Core) *Unseal {
	return &Unseal{core: core}
}

type UnsealRequest struct {
	Key []byte `json:"key"`
}

func (h *Unseal) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		if !h.core.IsSealed() {
			c.AbortWithStatus(http.StatusNotModified)
			return
		}

		var req UnsealRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "key is missing"})
			return
		}

		if err := h.core.Unseal(c, req.Key); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.Status(http.StatusOK)
	}
}
