package cli

import (
	"context"
	"strings"
)

type ICommand interface {
	Info() string
	Handle(ctx context.Context, b *strings.Builder, o *Operation) error
	Parse(args []string) error
}

type Commands map[string]ICommand

var AllCommands = Commands{
	"status":   NewStatusCommand(),
	"init":     NewInitCommand(),
	"unseal":   NewUnsealCommand(),
	"auth":     NewAuthCommand(),
	"engine":   NewEngineCommand(),
	"logopass": NewLogopassCommand(),
	"kv":       NewKvCommand(),
	"blob":     NewBlobCommand(),
	"pci_dss":  NewCommandPCI_DSS(),
}
