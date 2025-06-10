package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"path"
	"strings"
)

// EngineCommand представляет собой команду для управления движками. Доступные команды:
// - enable <engine_path> - включает авторизацию через указанный движок авторизации, например logopass или kv
// - disable <engine_path> - отключает авторизацию через указанный движок авторизации(не реализовано)
type EngineCommand struct {
	FSet *flag.FlagSet
}

var _ ICommand = &EngineCommand{}

func NewEngineCommand() *EngineCommand {
	c := &EngineCommand{
		FSet: flag.NewFlagSet("engine", flag.ExitOnError),
	}

	c.FSet.Usage = func() {
		fmt.Println("Usage: secman engine <operation> <engine_path> [<key>=<value>]")
		c.FSet.PrintDefaults()
	}

	return c
}

func (c *EngineCommand) Info() string {
	return "engine command"
}

func (c *EngineCommand) Parse(args []string) error {
	return c.FSet.Parse(args[1:])
}

// engine enable <engine_name>
// engine <engines operation> <engine_name>
func (c *EngineCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	if len(c.FSet.Args()) < 2 {
		return errors.New("engine command requires two arguments.\n\tExample usage: secman engine <engines operation> <engine_path>")
	}

	engineOperation := c.FSet.Arg(0)
	if engineOperation == "enable" {
		return c.enableEngine(ctx, b, o)
	}

	switch engineOperation {
	case "enable":
		return c.enableEngine(ctx, b, o)
	default:
		return errors.New("unknown engine operation")
	}
}

func (c *EngineCommand) enableEngine(ctx context.Context, b *strings.Builder, o *Operation) error {
	enginePath := c.FSet.Arg(1)

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	args := c.FSet.Args()
	payload := map[string]string{}

	if len(args) > 2 {
		for _, arg := range args[2:] {
			parts := strings.Split(arg, "=")
			if len(parts) != 2 {
				return errors.New("invalid argument: " + arg)
			}
			payload[parts[0]] = parts[1]
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := o.Client.Post(ctx, path.Join("sys", "engines", "enable", enginePath), bytes.NewReader(body), headers)
	if err != nil {
		if resp.Status == http.StatusNotFound {
			return errors.New("engine not found")
		}

		return err
	}

	b.WriteString("Successfull")
	return nil
}
