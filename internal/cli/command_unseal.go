package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"strconv"
	"strings"
)

type UnsealCommand struct {
	FSet *flag.FlagSet
	key  string
}

var _ ICommand = &UnsealCommand{}

func NewUnsealCommand() *UnsealCommand {
	cmd := &UnsealCommand{}
	cmd.FSet = flag.NewFlagSet("unseal", flag.ExitOnError)
	cmd.FSet.StringVar(&cmd.key, "k", "", "unseal key")
	return cmd
}

func (c *UnsealCommand) Info() string {
	return "unseal the secman server. This is only needed if the server is sealed."
}

func (c *UnsealCommand) Parse(args []string) error {
	return c.FSet.Parse(args[1:])
}

func (c *UnsealCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	headers := map[string]string{}

	// only admin can unseal the server
	rootToken, ok := o.Session.GetAuthProvider("root_token").GetToken(o.Session)
	if !ok {
		return errors.New("ROOT_TOKEN is not set, please set it with the env variable")
	}

	o.Session.Login(rootToken, "root_token")

	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	unsealPayload := map[string]string{
		"key": c.key,
	}
	payload, err := json.Marshal(unsealPayload)
	if err != nil {
		return err
	}

	resp, err := o.Client.Post(ctx, "sys/unseal", bytes.NewReader(payload), headers)
	if err != nil {
		if resp.Status == http.StatusBadRequest {
			return errors.New("invalid unseal key parts. Enter valid unseal key again")
		}

		return err
	}

	response, err := o.Client.Get(ctx, "sys/status", headers)
	if err != nil {
		return err
	}

	type StatusResponse struct {
		Barrier string `json:"barrier"`
		Sealed  bool   `json:"sealed"`
	}

	var status StatusResponse
	if err := json.NewDecoder(response.Body).Decode(&status); err != nil {
		return err
	}

	b.WriteString("Server sealed: " + strconv.FormatBool(status.Sealed) + "\n")
	b.WriteString("Barrier:       " + status.Barrier + "\n")

	return nil
}
