package cli

import (
	"context"
	"encoding/json"
	"flag"
	"strconv"
	"strings"
)

type StatusCommand struct {
	FSet *flag.FlagSet
}

func NewStatusCommand() *StatusCommand {
	cmd := &StatusCommand{}
	cmd.FSet = flag.NewFlagSet("status", flag.ExitOnError)
	return cmd
}

var _ ICommand = &StatusCommand{}

func (c *StatusCommand) Info() string {
	return "show information about the secman server. For example, version, build time, sealed status etc."
}

func (c *StatusCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	headers := map[string]string{}
	o.Session.Authenticate(headers)
	body, _, err := o.Client.Get(ctx, "sys/status", headers)
	if err != nil {
		return err
	}

	type StatusResponse struct {
		Barrier     string `json:"barrier"`
		Initialized bool   `json:"initialized"`
		Sealed      bool   `json:"sealed"`
	}

	var status StatusResponse
	if err := json.NewDecoder(body).Decode(&status); err != nil {
		return err
	}

	b.WriteString("Barrier:     " + status.Barrier + "\n")
	b.WriteString("Initialized: " + strconv.FormatBool(status.Initialized) + "\n")
	b.WriteString("Sealed:      " + strconv.FormatBool(status.Sealed) + "\n")

	return nil
}

func (c *StatusCommand) Parse(args []string) error {
	return c.FSet.Parse(args[1:])
}
