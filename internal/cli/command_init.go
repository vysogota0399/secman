package cli

import (
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"strings"
)

type InitCommand struct {
	FSet         *flag.FlagSet
	persistToken bool
}

func NewInitCommand() *InitCommand {
	cmd := &InitCommand{}
	cmd.FSet = flag.NewFlagSet("init", flag.ExitOnError)
	cmd.FSet.BoolVar(&cmd.persistToken, "pt", false, "persist the root token to the session. Works only if the server was not initialized. If pt is not set, save the root token to the environment variable ROOT_TOKEN.")
	return cmd
}

var _ ICommand = &InitCommand{}

func (c *InitCommand) Info() string {
	return "initialize the secman server. This is only needed if the server is not initialized."
}

func (c *InitCommand) Parse(args []string) error {
	return c.FSet.Parse(args[1:])
}

func (c *InitCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	initResp, code, err := o.Client.Post(ctx, "sys/init", nil, nil)
	if err != nil {
		return err
	}

	if code == http.StatusNotModified {
		b.WriteString("Server already initialized\n")
		return nil
	}

	type InitResponse struct {
		RootToken  string   `json:"root_token"`
		Thresholds []string `json:"thresholds"`
	}

	var initResponse InitResponse
	if err := json.NewDecoder(initResp).Decode(&initResponse); err != nil {
		return err
	}

	if c.persistToken {
		o.Session.SetRootToken(initResponse.RootToken)
	}

	b.WriteString("Server initialized successfully\n")
	b.WriteString("\nUse this token to authenticate as root, it will be needed for future operations. To use it, set the ROOT_TOKEN environment variable.\n")
	b.WriteString("Root token: " + initResponse.RootToken + "\n")
	b.WriteString("\nUse thresholds to unseal the server.\n")
	b.WriteString("Thresholds:\n")
	for _, threshold := range initResponse.Thresholds {
		b.WriteString("- " + threshold + "\n")
	}

	return nil
}
