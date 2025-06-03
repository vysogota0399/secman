package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"strings"
)

type AuthCommand struct {
	FSet   *flag.FlagSet
	enable bool
}

var _ ICommand = &AuthCommand{}

func NewAuthCommand() *AuthCommand {
	cmd := &AuthCommand{}
	cmd.FSet = flag.NewFlagSet("auth", flag.ExitOnError)
	cmd.FSet.BoolVar(&cmd.enable, "enable", false, "enable auth engine")
	return cmd
}

func (c *AuthCommand) Info() string {
	return "enable auth engine"
}

func (c *AuthCommand) Parse(args []string) error {
	return c.FSet.Parse(args[1:])
}

func (c *AuthCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	headers := map[string]string{}

	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	if c.enable {
		return c.enableAuth(ctx, o, b)
	}

	return errors.New("unknown command")
}

func (c *AuthCommand) enableAuth(ctx context.Context, o *Operation, b *strings.Builder) error {
	engineName := c.FSet.Arg(0)
	if engineName == "" {
		return errors.New("engine name is required.\n\tExample usage: secman auth -enable /auth/logopass")
	}

	headers := map[string]string{}

	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	payload := map[string]string{
		"engine_path": engineName,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := o.Client.Post(ctx, "sys/auth/enable", bytes.NewBuffer(jsonPayload), headers)
	if err != nil {
		if resp.Status == http.StatusNotFound {
			return errors.New("auth engine not found. If you want to enable such auth, enable engine first")
		}

		return err
	}

	b.WriteString("Successfull")
	return nil
}
