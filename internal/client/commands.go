package client

import "strings"

type Command struct {
	Subcommands map[string]Command
	Info        string
	Handler     func(args []string, b *strings.Builder) error
}

type Commands map[string]Command

var AllCommands = Commands{
	"status": {
		Info:        "show information about the secman server. For example, version, build time, sealed status etc.",
		Subcommands: map[string]Command{},
		Handler:     StatusHandler,
	},
}
