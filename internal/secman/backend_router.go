package secman

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

type BackendRouterNode struct {
	pattern  *regexp.Regexp
	Metadata *Path
	Fields   map[string]string
	Body     any
}

func (n *BackendRouterNode) ProcessPath(path string) (bool, error) {
	matches := n.pattern.FindStringSubmatch(path)

	// If no matches, return false
	if len(matches) == 0 {
		return false, nil
	}

	// If matches and no fields, return true
	if len(n.Metadata.Fields) == 0 {
		return true, nil
	}

	// If matches and fields, check if the number of matches is equal to the number of fields
	if len(matches)-1 != len(n.Metadata.Fields) {
		return false, fmt.Errorf("backend router: path %s does not match pattern: not enough fields", path)
	}

	// set fields
	for i, field := range n.Metadata.Fields {
		n.Fields[field.Name] = matches[i+1]
	}

	return true, nil
}

// BackendRouter is a router for a backend. It match incoming requests to the backend
// BackendRouter is a router for a backend. It match incoming requests to the backend
// Path and invoke the corresponding handler.
type BackendRouter struct {
	router map[string][]*BackendRouterNode
}

func NewBackendRouter(be LogicalBackend) (*BackendRouter, error) {
	router := map[string][]*BackendRouterNode{}

	for method, paths := range be.Paths() {
		if _, ok := router[method]; !ok {
			router[method] = []*BackendRouterNode{}
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

			router[method] = append(router[method], &BackendRouterNode{pattern: re, Metadata: pathInfo, Fields: make(map[string]string)})
		}
	}

	return &BackendRouter{router: router}, nil
}

func (r *BackendRouter) Handle(ctx *gin.Context) (*LogicalResponse, error) {
	method := ctx.Request.Method
	path := ctx.Request.URL.Path

	nodes, ok := r.router[method]
	if !ok {
		return &LogicalResponse{
			Status:  http.StatusNotFound,
			Message: "not found",
		}, nil
	}

	for _, node := range nodes {
		matched, err := node.ProcessPath(path)
		if err != nil {
			return &LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: "unsupported path params",
			}, nil
		}

		if !matched {
			continue
		}

		if node.Metadata.Body != nil {
			node.Body = node.Metadata.Body()

			if err := ctx.ShouldBindJSON(&node.Body); err != nil {
				return &LogicalResponse{
					Status:  http.StatusBadRequest,
					Message: "unsupported body schema",
				}, nil
			}
		}

		return node.Metadata.Handler(ctx, &LogicalParams{Params: node.Fields, Body: node.Body})
	}

	return &LogicalResponse{
		Status:  http.StatusNotFound,
		Message: "not found",
	}, nil
}
