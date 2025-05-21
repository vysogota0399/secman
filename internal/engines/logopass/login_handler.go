package logopass

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

func (b *Backend) LoginHandler(c *gin.Context, requestParams *secman.LogicalParams) (*secman.LogicalResponse, error) {
	body, ok := requestParams.Body.(*LoginPathBody)
	if !ok {
		return nil, fmt.Errorf("type cast error got %T, expected pointer", requestParams.Body)
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
