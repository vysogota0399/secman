package secman

import (
	"context"
	"errors"
	"io"

	"github.com/gin-gonic/gin"
)

var (
	ErrEngineAlreadyEnabled = errors.New("engine already enabled")
	ErrEngineIsNotEnabled   = errors.New("engine is not enabled")
	// ErrLogicalResponse is a error that is used to return logical response, not error
	ErrLogicalResponse = errors.New("") // empty message
)

// Backend is engine for manage secrets or other operations.
type LogicalBackend interface {
	RootPath() string
	Help() string
	// Paths returns a map of paths for the backend.
	// The key is the http method of the path.
	// The value is the route of the path.
	Paths() map[string]map[string]*Path
	// Enable is a function that enables the backend. It needs to initialize the backend
	// and save the result to storage
	Enable(ctx context.Context, req *LogicalRequest) (*LogicalResponse, error)
	// PostUnseal is a function that is called to restore backend state from storage
	PostUnseal(ctx context.Context) error
	Router() *BackendRouter
	SetRouter(router *BackendRouter)
}

// Field is a field of a path,
// Name is the name of the field,
// Description is the description of the field,
type Field struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type LogicalParams struct {
	Params map[string]string
	Body   any
}

// Path is a path of a backend
// Description is the description of the path,
// Handler is the handler of the path
// Fields is the fields of the path
// SkipAuth is a flag that indicates if the path should be skipped from authorization
type Path struct {
	Description string
	Handler     func(ctx *gin.Context, params *LogicalParams) (*LogicalResponse, error)
	// Body is the fields of the path, it is the data that will be sent to the handler
	Body     func() any
	Fields   []Field
	SkipAuth bool
}

// LogicalResponse is a response of a logical engine
// Status is the status of the response,
// Message is the message of the response,
// Data is the data of the response
type LogicalResponse struct {
	Status      int               `json:"status"`
	Message     any               `json:"message"`
	Headers     map[string]string `json:"headers"`
	Reader      io.ReadCloser     `json:"-"`
	ContentSize int64             `json:"-"`
}
type LogicalRequest struct {
	*gin.Context
}
