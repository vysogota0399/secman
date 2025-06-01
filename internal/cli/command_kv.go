package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
)

type KvCommand struct {
	FSet      *flag.FlagSet
	operation string
	key       string
	value     string
}

func NewKvCommand() *KvCommand {
	c := &KvCommand{
		FSet: flag.NewFlagSet("kv", flag.ExitOnError),
	}

	c.FSet.Usage = func() {
		fmt.Println("Usage: secman kv <operation> [-k <key>] [-v <value>]")
		c.FSet.PrintDefaults()
	}

	return c
}

var _ ICommand = &KvCommand{}

func (c *KvCommand) Info() string {
	return "kv command"
}

func (c *KvCommand) Parse(args []string) error {
	if len(args) < 2 {
		c.FSet.Usage()
		return nil
	}

	switch args[1] {
	case "write":
		c.FSet.StringVar(&c.key, "k", "", "key")
		c.FSet.StringVar(&c.value, "v", "", "value")
		c.operation = "write"
		return c.FSet.Parse(args[2:])
	case "read":
		c.FSet.StringVar(&c.key, "k", "", "key")
		c.operation = "read"
		return c.FSet.Parse(args[2:])
	case "delete":
		c.FSet.StringVar(&c.key, "k", "", "key")
		c.operation = "delete"
		return c.FSet.Parse(args[2:])
	}

	c.FSet.Usage()
	return nil
}

func (c *KvCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	switch c.operation {
	case "write":
		return c.write(ctx, b, o)
	case "read":
		return c.read(ctx, b, o)
	case "delete":
		return c.delete(ctx, b, o)
	}
	return nil
}

func (c *KvCommand) write(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.key == "" {
		return errors.New("key is required")
	}

	if c.value == "" {
		return errors.New("value is required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	payload := map[string]string{
		"key":   c.key,
		"value": c.value,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, _, err = o.Client.Post(ctx, "engine/secrets/kv", bytes.NewReader(body), headers)
	if err != nil {
		return err
	}

	b.WriteString("Successfull")
	return nil
}

func (c *KvCommand) read(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.key == "" {
		return errors.New("key is required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	response, statusCode, err := o.Client.Get(ctx, "engine/secrets/kv/"+c.key, headers)
	if err != nil {
		if statusCode == http.StatusNotFound {
			b.WriteString("Key:   " + c.key + "\n")
			b.WriteString("Error: secret not found\n")
			return nil
		}

		return err
	}

	resp := map[string]string{}
	if err := json.NewDecoder(response).Decode(&resp); err != nil {
		return err
	}

	b.WriteString("Key:   " + c.key + "\n")
	b.WriteString("Value: " + resp["value"] + "\n")
	return nil
}

func (c *KvCommand) delete(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.key == "" {
		return errors.New("key is required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	_, _, err := o.Client.Delete(ctx, "engine/secrets/kv/"+c.key, headers)
	if err != nil {
		return err
	}

	b.WriteString("Successfull")
	return nil
}
