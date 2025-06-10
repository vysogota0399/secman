package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/server"
	"go.uber.org/zap"
)

type EnableAuth struct {
	core *server.Core
}

func NewEnableAuth(core *server.Core) *EnableAuth {
	return &EnableAuth{core: core}
}

type EnableAuthRequest struct {
	EnginePath string `json:"engine_path"`
}

func (h *EnableAuth) Handler() func(c *gin.Context) {
	return func(c *gin.Context) {
		var req EnableAuthRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		be, err := h.core.Router.Resolve(req.EnginePath)
		if err != nil {
			h.core.Log.ErrorCtx(c.Request.Context(), "failed to resolve engine", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "engine " + req.EnginePath + " not found"})
			return
		}

		if err := h.core.Auth.EnableEngine(c.Request.Context(), be); err != nil {
			h.core.Log.ErrorCtx(c.Request.Context(), "failed to enable auth", zap.Error(err))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to enable auth engine, check logs for more details"})
		}

		c.JSON(http.StatusOK, gin.H{"message": "auth enabled"})
	}
}
