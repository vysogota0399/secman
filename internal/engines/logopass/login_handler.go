package logopass

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) LoginHandler(c *gin.Context) (*secman.LogicalResponse, error) {
	path := b.Paths()[http.MethodPost][b.logicalPath(c)]

	body := path.Body.(LoginPathBody)

	if err := c.ShouldBindJSON(&body); err != nil {
		return &secman.LogicalResponse{
			Status: http.StatusBadRequest,
			Message: gin.H{
				"error":  "invalid request body",
				"schema": path.Fields,
			},
		}, nil
	}

	user, err := b.logopass.Authenticate(c.Request.Context(), body.Login, body.Password)
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
