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

type CommandPCIDSS struct {
	FSet           *flag.FlagSet
	operation      string
	pan            string
	cardholderName string
	expiryDate     string
	securityCode   string

	panToken            string
	cardholderNameToken string
	expiryDateToken     string
	securityCodeToken   string
	showMetadata        bool
}

var _ ICommand = &CommandPCIDSS{}

func NewCommandPCIDSS() *CommandPCIDSS {
	c := &CommandPCIDSS{
		FSet: flag.NewFlagSet("pci_dss", flag.ExitOnError),
	}

	c.FSet.Usage = func() {
		fmt.Println("Usage: secman pci_dss <operation> [-p <pan>] [-cn <cardholderName>] [-ed <expiryDate>] [-sc <securityCode>] [-pt <panToken>] [-cct <cardholderNameToken>] [-edt <expiryDateToken>] [-sc <securityCodeToken>]")
		c.FSet.PrintDefaults()
	}

	return c
}

func (c *CommandPCIDSS) Info() string {
	return "PCI-DSS command for managing PCI-DSS secrets by secret tokens"
}

func (c *CommandPCIDSS) Parse(args []string) error {
	if len(args) < 2 {
		c.FSet.Usage()
		return nil
	}

	switch args[1] {
	case "write":
		c.operation = "write"
		c.FSet.StringVar(&c.pan, "p", "", "PAN ")
		c.FSet.StringVar(&c.cardholderName, "cn", "", "Cardholder Name")
		c.FSet.StringVar(&c.expiryDate, "ed", "", "Expiry Date")
		c.FSet.StringVar(&c.securityCode, "sc", "", "Security Code")
		return c.FSet.Parse(args[2:])
	case "read":
		c.operation = "read"
		c.FSet.StringVar(&c.panToken, "pt", "", "PAN Token")
		c.FSet.StringVar(&c.cardholderNameToken, "cct", "", "Cardholder Name Token")
		c.FSet.StringVar(&c.expiryDateToken, "edt", "", "Expiry Date Token")
		c.FSet.StringVar(&c.securityCodeToken, "sc", "", "Security Code Token")
		c.FSet.BoolVar(&c.showMetadata, "m", false, "Show Metadata")
		return c.FSet.Parse(args[2:])
	case "update":
		c.operation = "update"
		c.FSet.StringVar(&c.panToken, "pt", "", "PAN Token")
		return c.FSet.Parse(args[2:])
	case "delete":
		c.operation = "delete"
		c.FSet.StringVar(&c.panToken, "pt", "", "PAN Token")
		return c.FSet.Parse(args[2:])
	case "list":
		c.operation = "list"
		return c.FSet.Parse(args[2:])
	}

	return nil
}

func (c *CommandPCIDSS) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	switch c.operation {
	case "write":
		return c.write(ctx, b, o)
	case "read":
		return c.read(ctx, b, o)
	case "update":
		return c.update(ctx, b, o)
	case "delete":
		return c.delete(ctx, b, o)
	case "list":
		return c.list(ctx, b, o)
	}

	return nil
}

func (c *CommandPCIDSS) write(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.pan == "" {
		return errors.New("PAN is required")
	}

	if c.cardholderName == "" {
		return errors.New("cardholder Name is required")
	}

	if c.expiryDate == "" {
		return errors.New("expiry date is required")
	}

	if c.securityCode == "" {
		return errors.New("security code is required")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	payload := map[string]map[string]string{
		"card_data": {
			"pan":             c.pan,
			"cardholder_name": c.cardholderName,
			"expiry_date":     c.expiryDate,
			"security_code":   c.securityCode,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	response, err := o.Client.Post(ctx, "engine/secrets/pci_dss", bytes.NewReader(body), headers)
	if err != nil {
		return err
	}

	tokensResponse := map[string]string{}
	decorder := json.NewDecoder(response.Body)
	if err := decorder.Decode(&tokensResponse); err != nil {
		return err
	}

	b.WriteString("Successfull\n")
	b.WriteString("PAN token:             " + tokensResponse["pan"] + "\n")
	b.WriteString("Cardholder Name token: " + tokensResponse["cardholder_name"] + "\n")
	b.WriteString("Expiry Date token:     " + tokensResponse["expiry_date"] + "\n")
	b.WriteString("Security Code token:   " + tokensResponse["security_code"] + "\n")

	return nil
}

func (c *CommandPCIDSS) read(ctx context.Context, b *strings.Builder, o *Operation) error {
	route := "engine/secrets/pci_dss/" + c.panToken

	if c.panToken == "" {
		return errors.New("PAN token is required")
	}

	if c.cardholderNameToken != "" {
		route += "/cardholder_name/" + c.cardholderNameToken
	} else if c.expiryDateToken != "" {
		route += "/expiry_date/" + c.expiryDateToken
	} else if c.securityCodeToken != "" {
		route += "/security_code/" + c.securityCodeToken
	} else if c.showMetadata {
		route += "/metadata"
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	response, err := o.Client.Get(ctx, route, headers)
	if err != nil {
		if response.Status == http.StatusNotFound {
			b.WriteString("PAN token:   " + c.panToken + "\n")
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

func (c *CommandPCIDSS) update(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.panToken == "" {
		return errors.New("PAN token is required")
	}

	route := "engine/secrets/pci_dss/" + c.panToken + "/metadata"

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

	if _, err := o.Client.Put(ctx, route, bytes.NewReader(body), headers); err != nil {
		return err
	}

	b.WriteString("Successfull")

	return nil
}

func (c *CommandPCIDSS) delete(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.panToken == "" {
		return errors.New("PAN token is required")
	}

	route := "engine/secrets/pci_dss/" + c.panToken

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	if _, err := o.Client.Delete(ctx, route, headers); err != nil {
		return err
	}

	b.WriteString("Successfull")

	return nil
}

func (c *CommandPCIDSS) list(ctx context.Context, b *strings.Builder, o *Operation) error {
	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	response, err := o.Client.Get(ctx, "engine/secrets/pci_dss", headers)
	if err != nil {
		return err
	}

	type card struct {
		Key string `json:"key"`
	}

	resp := map[string][]card{}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return err
	}

	b.WriteString("Successfull\n")
	b.WriteString("Tokens count: " + strconv.Itoa(len(resp["value"])) + "\n")
	for _, v := range resp["value"] {
		b.WriteString(fmt.Sprintf("KEY: %s\n", v.Key))
	}
	return nil
}
