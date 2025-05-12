package secman

import "github.com/gin-gonic/gin"

type Engine interface {
	Factory(core *Core) Backend
}

type Backend interface {
	RootPath() string
	Help() string
	Paths() []*Path
	Enable() error
}

type Field struct {
	Name        string
	Description string
	Required    bool
}

type Path struct {
	Description string
	Path        string
	Method      string
	Handler     func(c *gin.Context)
	Fields      []Field
}

type LogicalResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}
