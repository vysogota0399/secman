package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
)

type BlobCommand struct {
	FSet         *flag.FlagSet
	operation    string
	filePath     string
	directory    string
	showMetadata bool
}

func NewBlobCommand() *BlobCommand {
	c := &BlobCommand{
		FSet: flag.NewFlagSet("blob", flag.ExitOnError),
	}

	c.FSet.Usage = func() {
		fmt.Println("Usage: secman blob <operation> <token> [meta <key>=<value>]")
		c.FSet.PrintDefaults()
	}

	return c
}

var _ ICommand = &BlobCommand{}

func (c *BlobCommand) Info() string {
	return "blob command for managing blob secrets"
}

func (c *BlobCommand) Parse(args []string) error {
	if len(args) < 2 {
		c.FSet.Usage()
		return nil
	}

	switch args[1] {
	case "write":
		c.operation = "write"
		c.FSet.StringVar(&c.filePath, "f", "", "path to the file to upload")

		return c.FSet.Parse(args[2:])
	case "read":
		c.operation = "read"
		c.FSet.BoolVar(&c.showMetadata, "m", false, "show metadata")
		c.FSet.StringVar(&c.directory, "d", "", "directory to save the file")
		return c.FSet.Parse(args[2:])
	case "delete":
		c.operation = "delete"
		return c.FSet.Parse(args[2:])
	case "update":
		c.operation = "update"
		return c.FSet.Parse(args[2:])
	}

	c.FSet.Usage()
	return nil
}

func (c *BlobCommand) Handle(ctx context.Context, b *strings.Builder, o *Operation) error {
	switch c.operation {
	case "write":
		return c.write(ctx, b, o)
	case "read":
		return c.read(ctx, b, o)
	case "delete":
		return c.delete(ctx, b, o)
	case "update":
		return c.update(ctx, b, o)
	}

	return nil
}

func (c *BlobCommand) write(ctx context.Context, b *strings.Builder, o *Operation) error {
	if c.filePath == "" {
		return errors.New("source path is required")
	}

	file, err := os.OpenFile(c.filePath, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	headers := map[string]string{
		"Content-Type": "multipart/form-data",
	}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	route := "engine/secrets/blobs"

	response, err := o.Client.MultipartRequest(ctx, "POST", route, headers, map[string]string{}, &Blob{
		FieldName: "file",
		FileName:  c.filePath,
		Reader:    file,
	})

	if err != nil {
		return err
	}

	resp := map[string]string{}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(&resp); err != nil {
		return err
	}

	b.WriteString("Successfull\n")
	b.WriteString("Token: " + resp["token"])
	return nil
}

func (c *BlobCommand) read(ctx context.Context, b *strings.Builder, o *Operation) error {
	token := c.FSet.Arg(0)
	if token == "" {
		return errors.New("token is required. Example: secman blob read -d <path> <token>")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	route := "engine/secrets/blobs/" + token

	if c.showMetadata {
		route += "/metadata"
	}

	response, err := o.Client.Get(ctx, route, headers)
	if err != nil {
		if response.Status == http.StatusNotFound {
			return errors.New("secret not found")
		}

		return err
	}

	if c.showMetadata {
		return c.processMetadata(b, response)
	}

	return c.processFile(b, response)
}

func (c *BlobCommand) delete(ctx context.Context, b *strings.Builder, o *Operation) error {
	token := c.FSet.Arg(0)
	if token == "" {
		return errors.New("token is required. Example: secman blob delete <token>")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	route := "engine/secrets/blobs/" + token

	if response, err := o.Client.Delete(ctx, route, headers); err != nil {
		if response.Status == http.StatusNotFound {
			return errors.New("secret not found")
		}

		return err
	}

	b.WriteString("Successfull")
	return nil
}

func (c *BlobCommand) update(ctx context.Context, b *strings.Builder, o *Operation) error {
	token := c.FSet.Arg(0)
	if token == "" {
		return errors.New("token is required. Example: secman blob update <token>")
	}

	headers := map[string]string{}
	if err := o.Session.Authenticate(headers); err != nil {
		return err
	}

	route := "engine/secrets/blobs/" + token + "/metadata"

	payload := map[string]map[string]string{
		"metadata": {},
	}
	args := c.FSet.Args()
	for _, arg := range args[1:] {
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

func (c *BlobCommand) processMetadata(b *strings.Builder, response *Response) error {
	b.WriteString("Successfull\n")
	resp := map[string]any{}
	if err := json.NewDecoder(response.Body).Decode(&resp); err != nil {
		return err
	}

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

func (c *BlobCommand) processFile(b *strings.Builder, response *Response) error {
	fileInfo := response.Headers["Content-Disposition"]
	if fileInfo == "" {
		return errors.New("server invalid response - file info is required")
	}

	parts := strings.Split(fileInfo, ";")
	fileName := strings.TrimSpace(parts[1])
	fileName = strings.Split(fileName, "=")[1]

	if fileName == "" {
		return errors.New("server invalid response - file name is required")
	}

	path := path.Join(c.directory, fileName)

	file, err := os.Create(path)
	if err != nil {
		return err
	}

	defer file.Close()

	io.Copy(file, response.Body)

	b.WriteString("Successfull\n")
	b.WriteString("File saved to " + path)
	return nil
}
