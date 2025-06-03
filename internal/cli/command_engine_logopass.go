package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
)

type LogopassCommand struct {
	FSet      *flag.FlagSet
	username  string
	password  string
	operation string
}

func NewLogopassCommand() *LogopassCommand {
	c := &LogopassCommand{
		FSet: flag.NewFlagSet("logopass", flag.ExitOnError),
	}

	// Define flags in constructor
	c.FSet.Usage = func() {
		fmt.Println("Usage: secman logopass <operation> [-u <username>] [-p <password>]")
		c.FSet.PrintDefaults()
	}

	return c
}

var _ ICommand = &LogopassCommand{}

func (c *LogopassCommand) Info() string {
	return "logopass command"
}

func (c *LogopassCommand) Parse(args []string) error {
	if len(args) < 2 {
		c.FSet.Usage()
		return nil
	}

	switch args[1] {
	case "login":
		c.FSet.StringVar(&c.username, "u", "", "username")
		c.FSet.StringVar(&c.password, "p", "", "password")
		c.operation = "login"
		return c.FSet.Parse(args[2:])
	case "register":
		c.FSet.StringVar(&c.username, "u", "", "username")
		c.FSet.StringVar(&c.password, "p", "", "password")
		c.operation = "register"
		// Parse only the remaining arguments after the command
		return c.FSet.Parse(args[2:])
	}

	c.FSet.Usage()
	return nil
}

func (c *LogopassCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	switch c.operation {
	case "login":
		return c.handleLogin(ctx, b, o)
	case "register":
		return c.handleRegister(ctx, b, o)
	}

	return nil
}

func (c *LogopassCommand) handleLogin(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.username == "" || c.password == "" {
		return errors.New("username and password are required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	payload := map[string]string{
		"login":    c.username,
		"password": c.password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := o.Client.Post(ctx, "engine/auth/logopass/login", bytes.NewReader(body), headers)
	if err != nil {
		return err
	}

	type LoginResponse struct {
		Token string `json:"token"`
	}

	var loginResponse LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&loginResponse); err != nil {
		return err
	}

	o.Session.Login(loginResponse.Token, "logopass")

	b.WriteString("Successfull")
	return nil
}

func (c *LogopassCommand) handleRegister(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.username == "" || c.password == "" {
		return errors.New("username and password are required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	payload := map[string]string{
		"login":    c.username,
		"password": c.password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = o.Client.Post(ctx, "engine/auth/logopass/register", bytes.NewReader(body), headers)
	if err != nil {
		return err
	}

	b.WriteString("Successfull")
	return nil
}
