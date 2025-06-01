package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"path"
)

type Client struct {
	session ISession
	client  *http.Client
	config  *Config
}

type IClient interface {
	Post(ctx context.Context, path string, body io.Reader, headers map[string]string) (io.Reader, int, error)
	Get(ctx context.Context, path string, headers map[string]string) (io.Reader, int, error)
	Put(ctx context.Context, path string, body io.Reader, headers map[string]string) (io.Reader, int, error)
	Delete(ctx context.Context, path string, headers map[string]string) (io.Reader, int, error)
}

var _ IClient = &Client{}

func NewClient(s ISession, c *Config) (*Client, error) {
	if c.ServerURL == "" {
		return nil, errors.New("server URL is required")
	}

	cl := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: c.SSLSkipVerify,
			},
		},
	}

	return &Client{
		session: s,
		client:  &cl,
		config:  c,
	}, nil
}

func (c *Client) Post(ctx context.Context, route string, body io.Reader, headers map[string]string) (io.Reader, int, error) {
	req, err := c.NewRequest(http.MethodPost, route, body, headers)
	if err != nil {
		return nil, 0, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

func (c *Client) Get(ctx context.Context, route string, headers map[string]string) (io.Reader, int, error) {
	req, err := c.NewRequest(http.MethodGet, route, nil, headers)
	if err != nil {
		return nil, 0, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

func (c *Client) Put(ctx context.Context, route string, body io.Reader, headers map[string]string) (io.Reader, int, error) {
	return nil, 0, nil
}

func (c *Client) Delete(ctx context.Context, route string, headers map[string]string) (io.Reader, int, error) {
	req, err := c.NewRequest(http.MethodDelete, route, nil, headers)
	if err != nil {
		return nil, 0, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, 0, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

func (c *Client) NewUrl(route string) string {
	route = path.Join("/api", route)
	return c.config.ServerURL + route
}

func (c *Client) NewRequest(method string, route string, body io.Reader, headers map[string]string) (*http.Request, error) {
	url := c.NewUrl(route)
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

func (c *Client) CopyBuffer(resp *http.Response) (io.Reader, error) {
	response := bytes.NewBuffer(nil)
	_, err := io.Copy(response, resp.Body)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (c *Client) HandleResponse(resp *http.Response) (io.Reader, int, error) {
	defer resp.Body.Close()

	switch code := resp.StatusCode; code {
	case http.StatusUnauthorized:
		c.session.TruncateSecrets()
		return nil, code, errors.New("unauthorized, please authenticate with the server")
	case http.StatusNotFound:
		return nil, code, errors.New("no route matched the specified path " + c.NewUrl(resp.Request.URL.Path))
	case http.StatusServiceUnavailable:
		return nil, code, errors.New("server is sealed, please unseal it first")
	case http.StatusInternalServerError:
		return nil, code, errors.New("internal server error, for more details see logs")
	case http.StatusBadRequest:
		body, err := c.CopyBuffer(resp)
		if err != nil {
			return nil, code, err
		}

		response, err := io.ReadAll(body)
		if err != nil {
			return nil, code, err
		}

		return nil, code, errors.New(string(response))
	default:
		body, err := c.CopyBuffer(resp)
		if err != nil {
			return nil, code, err
		}

		return body, code, nil
	}
}
