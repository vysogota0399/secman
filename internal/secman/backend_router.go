package secman

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap"
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
	lg     *logging.ZapLogger
}

func NewBackendRouter(be LogicalBackend, lg *logging.ZapLogger) (*BackendRouter, error) {
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
					regexpParts[i] = "(.+)"
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

		// sort nodes by length of pattern, longest first to match the most specific pattern first
		sort.Slice(router[method], func(i, j int) bool {
			return len(router[method][i].pattern.String()) > len(router[method][j].pattern.String())
		})
	}

	return &BackendRouter{router: router, lg: lg}, nil
}

func (r *BackendRouter) Handle(ctx *gin.Context) (*LogicalResponse, error) {
	method := ctx.Request.Method
	path := ctx.Request.URL.Path

	nodes, ok := r.router[method]
	if !ok {
		return &LogicalResponse{
			Status:  http.StatusNotFound,
			Message: gin.H{"error": "not found"},
		}, nil
	}

	for _, node := range nodes {
		matched, err := node.ProcessPath(path)
		if err != nil {
			r.lg.ErrorCtx(ctx.Request.Context(), "backend router: process path failed", zap.Error(err), zap.String("path", path))
			return &LogicalResponse{
				Status:  http.StatusBadRequest,
				Message: gin.H{"error": "unsupported path params"},
			}, nil
		}

		if !matched {
			continue
		}

		if node.Metadata.Body != nil {
			body := node.Metadata.Body()

			if ctx.Request.Header.Get("Content-Type") == "application/json" {
				if err := ctx.ShouldBindJSON(body); err != nil {
					return &LogicalResponse{
						Status:  http.StatusBadRequest,
						Message: gin.H{"error": "unsupported body schema"},
					}, nil
				}
			}

			if ctx.Request.Header.Get("Content-Type") == "multipart/form-data" {
				if err := ctx.ShouldBindWith(body, binding.FormMultipart); err != nil {
					return &LogicalResponse{
						Status:  http.StatusBadRequest,
						Message: gin.H{"error": "unsupported body schema"},
					}, nil
				}
			}
			node.Body = body
		}

		return node.Metadata.Handler(ctx.Request.Context(), &LogicalRequest{Context: ctx}, &LogicalParams{Params: node.Fields, Body: node.Body})
	}

	return &LogicalResponse{
		Status:  http.StatusNotFound,
		Message: gin.H{"error": "not found"},
	}, nil
}
