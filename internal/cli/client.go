package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"path"
	"strings"

	"github.com/vysogota0399/secman/internal/logging"
	"go.uber.org/zap"
)

type Client struct {
	session ISession
	client  HTTP
	config  *Config
	lg      *logging.ZapLogger
}

type IClient interface {
	Post(ctx context.Context, path string, body io.Reader, headers map[string]string) (*Response, error)
	Get(ctx context.Context, path string, headers map[string]string) (*Response, error)
	Put(ctx context.Context, path string, body io.Reader, headers map[string]string) (*Response, error)
	Delete(ctx context.Context, path string, headers map[string]string) (*Response, error)
	MultipartRequest(ctx context.Context, method string, route string, headers map[string]string, fields map[string]string, files ...*Blob) (*Response, error)
}

type Response struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    io.Reader         `json:"body"`
}

type HTTP interface {
	Do(req *http.Request) (*http.Response, error)
}

var _ IClient = &Client{}

func NewClient(s ISession, c *Config, lg *logging.ZapLogger) (*Client, error) {
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
		lg:      lg,
	}, nil
}

func (c *Client) Post(ctx context.Context, route string, body io.Reader, headers map[string]string) (*Response, error) {
	req, err := c.NewRequest(http.MethodPost, route, body, headers)
	if err != nil {
		return &Response{}, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return &Response{}, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

func (c *Client) Get(ctx context.Context, route string, headers map[string]string) (*Response, error) {
	req, err := c.NewRequest(http.MethodGet, route, nil, headers)
	if err != nil {
		return &Response{}, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return &Response{}, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

func (c *Client) Put(ctx context.Context, route string, body io.Reader, headers map[string]string) (*Response, error) {
	req, err := c.NewRequest(http.MethodPut, route, body, headers)
	if err != nil {
		return &Response{}, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return &Response{}, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

func (c *Client) Delete(ctx context.Context, route string, headers map[string]string) (*Response, error) {
	req, err := c.NewRequest(http.MethodDelete, route, nil, headers)
	if err != nil {
		return &Response{}, err
	}

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return &Response{}, err
	}

	defer resp.Body.Close()

	return c.HandleResponse(resp)
}

type Blob struct {
	FieldName string
	FileName  string
	Reader    io.Reader
}

func (c *Client) MultipartRequest(
	ctx context.Context,
	method string,
	route string,
	headers map[string]string,
	fields map[string]string,
	files ...*Blob,
) (*Response, error) {

	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)

	for k, v := range fields {
		w.WriteField(k, v)
	}

	for _, file := range files {
		part, err := w.CreateFormFile(file.FieldName, file.FileName)
		if err != nil {
			return &Response{}, err
		}

		_, err = io.Copy(part, file.Reader)
		if err != nil {
			return &Response{}, err
		}
	}

	w.Close()

	req, err := c.NewRequest(method, route, body, headers)
	if err != nil {
		return &Response{}, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := c.client.Do(req.WithContext(ctx))
	if err != nil {
		return &Response{}, err
	}

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

func (c *Client) HandleResponse(resp *http.Response) (*Response, error) {
	defer resp.Body.Close()

	headers := make(map[string]string, len(resp.Header))
	for k, v := range resp.Header {
		headers[k] = v[0]
	}

	switch code := resp.StatusCode; code {
	case http.StatusUnauthorized:
		return &Response{
			Status:  code,
			Headers: headers,
		}, errors.New("unauthorized, please authenticate with the server")
	case http.StatusNotFound:
		return &Response{
			Status:  code,
			Headers: headers,
		}, errors.New("no route matched the specified path " + c.NewUrl(resp.Request.URL.Path))
	case http.StatusServiceUnavailable:
		return &Response{
			Status:  code,
			Headers: headers,
		}, errors.New("server is sealed, please unseal it first")
	case http.StatusInternalServerError:
		return &Response{
			Status:  code,
			Headers: headers,
		}, errors.New("internal server error, for more details see logs")
	case http.StatusConflict:
		return &Response{
			Status:  code,
			Headers: headers,
		}, errors.New("secret already exists")
	case http.StatusBadRequest:
		r := map[string]string{}
		decorder := json.NewDecoder(resp.Body)
		if err := decorder.Decode(&r); err != nil {
			return &Response{
				Status:  code,
				Headers: headers,
				Body:    resp.Body,
			}, errors.New(r["error"])
		}

		return &Response{
			Status:  http.StatusBadRequest,
			Headers: headers,
		}, errors.New(r["error"])
	default:
		body, err := c.CopyBuffer(resp)
		if err != nil {
			return &Response{
				Status:  code,
				Headers: headers,
				Body:    resp.Body,
			}, err
		}

		r := &Response{
			Status:  http.StatusOK,
			Headers: headers,
			Body:    body,
		}

		cache, err := json.Marshal(r)
		if err != nil {
			return &Response{
				Status:  code,
				Headers: headers,
				Body:    resp.Body,
			}, err
		}

		c.session.Set(path.Join(strings.ToLower(resp.Request.Method), resp.Request.URL.Path), string(cache))

		return r, nil
	}
}

type ClientCacheWrapper struct {
	client  IClient
	lg      *logging.ZapLogger
	session ISession
}

var _ IClient = &ClientCacheWrapper{}

func NewClientCacheWrapper(client IClient, session ISession, lg *logging.ZapLogger) *ClientCacheWrapper {
	return &ClientCacheWrapper{
		client:  client,
		session: session,
		lg:      lg,
	}
}

func (c *ClientCacheWrapper) Post(ctx context.Context, route string, body io.Reader, headers map[string]string) (*Response, error) {
	return c.client.Post(ctx, route, body, headers)
}

func (c *ClientCacheWrapper) Get(ctx context.Context, route string, headers map[string]string) (*Response, error) {
	response, err := c.client.Get(ctx, route, headers)
	if err != nil {
		return c.FromSessinOrError(ctx, err, route)
	}

	c.SaveResponse(ctx, route, response)
	return response, nil
}

func (c *ClientCacheWrapper) Put(ctx context.Context, route string, body io.Reader, headers map[string]string) (*Response, error) {
	return c.client.Put(ctx, route, body, headers)
}

func (c *ClientCacheWrapper) Delete(ctx context.Context, route string, headers map[string]string) (*Response, error) {
	return c.client.Delete(ctx, route, headers)
}

func (c *ClientCacheWrapper) MultipartRequest(ctx context.Context, method string, route string, headers map[string]string, fields map[string]string, files ...*Blob) (*Response, error) {
	return c.client.MultipartRequest(ctx, method, route, headers, fields, files...)
}

type ResponseCache struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

func NewResponseCache(response *Response) *ResponseCache {
	buf := &bytes.Buffer{}
	_, err := io.Copy(buf, response.Body)
	if err != nil {
		return &ResponseCache{}
	}

	response.Body = buf

	return &ResponseCache{
		Status:  response.Status,
		Headers: response.Headers,
		Body:    buf.Bytes(),
	}
}

func (r *ResponseCache) ToResponse() *Response {
	return &Response{
		Status:  r.Status,
		Headers: r.Headers,
		Body:    bytes.NewReader(r.Body),
	}
}

func (c *ClientCacheWrapper) FromSessinOrError(ctx context.Context, err error, route string) (*Response, error) {
	dialErr, ok := errors.Unwrap(err).(*net.OpError)
	if !ok {
		return &Response{}, err
	}

	if dialErr.Op != "dial" {
		return &Response{}, err
	}

	c.lg.DebugCtx(ctx, "dial tcp connection error, trying to get secret from session", zap.String("route", route))

	secret, ok := c.session.Get(route)
	if !ok {
		c.lg.DebugCtx(ctx, "no secret found in session, returning error")
		return &Response{}, err
	}

	cache := &ResponseCache{}
	if err := json.Unmarshal([]byte(secret), cache); err != nil {
		c.lg.DebugCtx(ctx, "failed to unmarshal secret, returning error")
		return &Response{}, err
	}

	c.lg.DebugCtx(ctx, "secret found in session, returning response", zap.Any("response", cache))

	return cache.ToResponse(), nil
}

func (c *ClientCacheWrapper) SaveResponse(ctx context.Context, route string, response *Response) {
	cache := NewResponseCache(response)
	cacheJson, err := json.Marshal(cache)
	if err != nil {
		c.lg.ErrorCtx(ctx, "failed to marshal cache", zap.Error(err))
		return
	}

	c.session.Set(route, string(cacheJson))
}
