package logopass

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

type LoginRequest struct {
	Login    string `json:"login" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (b *Backend) LoginHandler(c *gin.Context) (*secman.LogicalResponse, error) {
	path := b.Paths()[http.MethodPost][b.logicalPath(c)]

	var request LoginRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		return &secman.LogicalResponse{
			Status: http.StatusBadRequest,
			Message: gin.H{
				"error":  "invalid request body",
				"schema": path.Fields,
			},
		}, nil
	}

	user, err := b.logopass.Authenticate(c.Request.Context(), request.Login, request.Password)
	if err != nil {
		return &secman.LogicalResponse{
			Status:  http.StatusUnauthorized,
			Message: gin.H{"error": "invalid credentials"},
		}, nil
	}

	token, err := b.logopass.Login(c.Request.Context(), user, b)
	if err != nil {
		return &secman.LogicalResponse{
			Status:  http.StatusInternalServerError,
			Message: gin.H{"error": "failed to login"},
		}, nil
	}

	return &secman.LogicalResponse{
		Status:  http.StatusOK,
		Message: gin.H{"token": token},
	}, nil
}
