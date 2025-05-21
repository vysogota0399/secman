package logopass

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/vysogota0399/secman/internal/secman"
)

type Node struct {
	pattern  *regexp.Regexp
	metadata *secman.Path
}

type Router struct {
	router map[string][]*Node
}

func NewRouter(be *Backend) (*Router, error) {
	router := map[string][]*Node{}

	for method, paths := range be.Paths() {
		if _, ok := router[method]; !ok {
			router[method] = []*Node{}
		}

		for pattern, pathInfo := range paths {
			patternParts := strings.Split(pattern, "/")
			regexpParts := make([]string, len(patternParts))

			for i, part := range patternParts {
				if strings.HasPrefix(part, ":") {
					regexpParts[i] = "([^/]+)"
				} else {
					// Escape special regexp characters
					regexpParts[i] = regexp.QuoteMeta(part)
				}
			}

			regexpPattern := strings.Join(regexpParts, "/") + "$"
			re, err := regexp.Compile(regexpPattern)
			if err != nil {
				return nil, fmt.Errorf("logopass: compile regexp failed error: %w", err)
			}

			router[method] = append(router[method], &Node{pattern: re, metadata: pathInfo})
		}
	}

	return &Router{router: router}, nil
}

func (r *Router) Handle(ctx *gin.Context) (*secman.LogicalResponse, error) {
	return nil, nil
}
