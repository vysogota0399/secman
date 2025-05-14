package secman

import (
	"context"

	"github.com/gin-gonic/gin"
)

// Engine is a logical engine that can be used to create a backend
type Engine interface {
	Name() string
	Factory(core *Core) Backend
}

// Backend is a logical backend that can be used to create a path
type Backend interface {
	RootPath() string
	Help() string
	Paths() []*Path
	Enable(ctx context.Context, req *LogicalRequest) (*LogicalResponse, error)
	Mount(ctx context.Context) error
}

// Field is a field of a path,
// Name is the name of the field,
// Description is the description of the field,
// Required is a flag that indicates if the field is required
type Field struct {
	Name        string
	Description string
	Required    bool
}

// Path is a path of a backend
// Description is the description of the path,
// Path is the path of the path
// Method is the method of the path
// Handler is the handler of the path
// Fields is the fields of the path
type Path struct {
	Description string
	Path        string
	Method      string
	Handler     func(ctx *gin.Context) (*LogicalResponse, error)
	Fields      []Field
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
