package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// KvCommand представляет собой команду для управления секретами в формате ключ значение. Доступные команды:
// - write <key> <value> - записывает секрет в сервис
// - read <key> - читает секрет из сервиса/читает его метаданные
// - delete <key> - удаляет секрет из сервиса
// - update <key> <key>=<value> - обновляет метаданные секрета
// - list - выводит список всех секретов
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
		fmt.Println("Usage: secman kv <operation> [-k <key>] [-v <value>] -fiz=<baz>...")
		c.FSet.PrintDefaults()
	}

	return c
}

var _ ICommand = &KvCommand{}

func (c *KvCommand) Info() string {
	return "kv command for managing kv secrets"
}

func (c *KvCommand) Parse(args []string) error {
	if len(args) < 2 {
		c.FSet.Usage()
		return nil
	}

	// Define flags first
	c.FSet.StringVar(&c.key, "k", "", "key")

	switch args[1] {
	case "write":
		c.FSet.StringVar(&c.value, "v", "", "value")
		c.operation = "write"
		return c.FSet.Parse(args[2:])
	case "read":
		c.operation = "read"
		return c.FSet.Parse(args[2:])
	case "update":
		c.operation = "update"
		return c.FSet.Parse(args[2:])
	case "delete":
		c.operation = "delete"
		return c.FSet.Parse(args[2:])

	case "list":
		c.operation = "list"
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
	case "update":
		return c.update(ctx, b, o)
	case "list":
		return c.list(ctx, b, o)
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

	_, err = o.Client.Post(ctx, "engine/secrets/kv", bytes.NewReader(body), headers)
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

	response, err := o.Client.Get(ctx, "engine/secrets/kv/"+c.key, headers)
	if err != nil {
		if response.Status == http.StatusNotFound {
			b.WriteString("Key:   " + c.key + "\n")
			b.WriteString("Error: secret not found\n")
			return nil
		}

		return err
	}

	resp := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return err
	}

	b.WriteString("Successfull\n")
	for k, v := range resp {
		if vmap, ok := v.(map[string]any); ok {
			secrets := make([]string, 0, 20*len(vmap))

			for k, v := range vmap {
				secrets = append(secrets, k+": "+fmt.Sprintf("%v", v))
			}

			b.WriteString(strings.Join(secrets, "\n"))
		} else {
			b.WriteString(k + ": " + fmt.Sprintf("%v", v))
		}
	}

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

	if _, err := o.Client.Delete(ctx, "engine/secrets/kv/"+c.key, headers); err != nil {
		return err
	}

	b.WriteString("Successfull")
	return nil
}

func (c *KvCommand) update(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.key == "" {
		return errors.New("key is required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	payload := map[string]map[string]string{
		"metadata": {},
	}

	args := c.FSet.Args()
	for _, arg := range args {
		parts := strings.Split(arg, "=")
		if len(parts) != 2 {
			return errors.New("invalid argument: " + arg)
		}
		payload["metadata"][parts[0]] = parts[1]
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	if _, err := o.Client.Put(ctx, "engine/secrets/kv/"+c.key, bytes.NewReader(body), headers); err != nil {
		return err
	}

	b.WriteString("Successfull")
	return nil
}

func (c *KvCommand) list(ctx context.Context, b *strings.Builder, o *Operation) error {
	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	response, err := o.Client.Get(ctx, "engine/secrets/kv", headers)
	if err != nil {
		return err
	}

	type secret struct {
		Key string `json:"key"`
	}

	resp := map[string][]secret{}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return err
	}

	b.WriteString("Successfull\n")
	b.WriteString("KEYS COUNT: " + strconv.Itoa(len(resp["value"])) + "\n")
	for _, v := range resp["value"] {
		b.WriteString(fmt.Sprintf("KEY: %s\n", v.Key))
	}

	return nil
}
