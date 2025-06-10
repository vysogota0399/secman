package logopass

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
)

func (b *Backend) Authorize(c *gin.Context) (bool, error) {
	// Skip authorization for paths that are marked as skipAuth
	// for example, login and register
	if b.skipAuth(c) {
		return true, nil
	}

	authToken := c.GetHeader("Authorization")
	if authToken == "" {
		return false, nil
	}

	jwToken, err := b.findToken(authToken)
	if err != nil {
		return false, nil
	}

	if err := b.logopass.Authorize(c.Request.Context(), jwToken, b); err != nil {
		return false, err
	}

	return true, nil
}

func (b *Backend) findToken(header string) (string, error) {
	match := b.tokenReg.FindStringSubmatch(header)

	if len(match) < 2 {
		return "", errors.New("logopass: failed to find token")
	}

	return match[1], nil
}

func (b *Backend) skipAuth(c *gin.Context) bool {
	paths := b.Paths()[c.Request.Method]
	if paths == nil {
		return false
	}

	path, ok := paths[b.logicalPath(c)]
	if !ok {
		return false
	}

	return path.SkipAuth
}

func (b *Backend) logicalPath(c *gin.Context) string {
	originalPath := c.Request.URL.Path
	idx := strings.Index(originalPath, b.RootPath())
	if idx == -1 {
		return ""
	}

	return originalPath[idx:]
}
