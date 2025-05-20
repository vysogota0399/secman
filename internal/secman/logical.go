package secman

import (
	"context"
	"errors"

	"github.com/gin-gonic/gin"
)

var (
	ErrEngineAlreadyEnabled = errors.New("engine already enabled")
	ErrEngineIsNotEnabled   = errors.New("engine is not enabled")
)

// Backend is engine for manage secrets or other operations
type LogicalBackend interface {
	RootPath() string
	Help() string
	// Paths returns a map of paths for the backend.
	// The key is the http method of the path.
	// The value is the route of the path.
	Paths() map[string]map[string]*Path
	Enable(ctx context.Context, req *LogicalRequest) (*LogicalResponse, error)
	PostUnseal(ctx context.Context) error
}

// Field is a field of a path,
// Name is the name of the field,
// Description is the description of the field,
// Required is a flag that indicates if the field is required
type Field struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
}

// Path is a path of a backend
// Description is the description of the path,
// Handler is the handler of the path
// Fields is the fields of the path
// SkipAuth is a flag that indicates if the path should be skipped from authorization
type Path struct {
	Description string
	Handler     func(ctx *gin.Context) (*LogicalResponse, error)
	Fields      []Field
	SkipAuth    bool
}

// LogicalResponse is a response of a logical engine
// Status is the status of the response,
// Message is the message of the response,
// Data is the data of the response
type LogicalResponse struct {
	Status  int `json:"status"`
	Message any `json:"message"`
}
type LogicalRequest struct {
	*gin.Context
}
