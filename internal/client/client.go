package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// Response représente une réponse HTTP.
type Response struct {
	StatusCode int
	Body       string
	Headers    http.Header
	Duration   time.Duration
	URL        string
}

// HTTPClient envoie des requêtes HTTP configurables.
type HTTPClient struct {
	client          *http.Client
	headers         map[string]string
	cookies         map[string]string
	followRedirects bool
}

// New crée un client HTTP.
func New(timeoutSec int, headers, cookies map[string]string) *HTTPClient {
	c := &HTTPClient{
		headers:         headers,
		cookies:         cookies,
		followRedirects: true,
	}
	c.client = &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.followRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return fmt.Errorf("trop de redirections")
			}
			return nil
		},
	}
	return c
}

// WithoutRedirects retourne une copie qui ne suit pas les redirections.
func (c *HTTPClient) WithoutRedirects() *HTTPClient {
	clone := *c
	clone.followRedirects = false
	clone.client = &http.Client{
		Timeout: c.client.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &clone
}

// Send envoie une requête avec un paramètre injecté.
func (c *HTTPClient) Send(ctx context.Context, target models.ScanTarget, paramName, payload string) (Response, error) {
	reqURL, method, bodyReader, contentType, err := buildRequest(target, paramName, payload)
	if err != nil {
		return Response{}, err
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return Response{}, err
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	for k, v := range c.cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	for k, v := range target.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "sqli-hunter/1.0 (bug-bounty)")
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return Response{}, err
	}

	return Response{
		StatusCode: resp.StatusCode,
		Body:       string(raw),
		Headers:    resp.Header.Clone(),
		Duration:   time.Since(start),
		URL:        reqURL,
	}, nil
}

func buildRequest(target models.ScanTarget, paramName, payload string) (string, string, io.Reader, string, error) {
	method := strings.ToUpper(target.Method)
	if method == "" {
		method = "GET"
	}

	if target.JSONBody != nil {
		return buildJSONRequest(target, paramName, payload, method)
	}

	if method == "GET" || len(target.Data) == 0 {
		return buildGETRequest(target, paramName, payload, method)
	}

	return buildFormRequest(target, paramName, payload, method)
}

func buildGETRequest(target models.ScanTarget, paramName, payload, method string) (string, string, io.Reader, string, error) {
	u, err := url.Parse(target.URL)
	if err != nil {
		return "", "", nil, "", err
	}

	q := u.Query()
	params := target.Params
	if params == nil {
		params = make(map[string]string)
	}
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set(paramName, payload)
	u.RawQuery = q.Encode()

	return u.String(), method, nil, "", nil
}

func buildFormRequest(target models.ScanTarget, paramName, payload, method string) (string, string, io.Reader, string, error) {
	data := url.Values{}
	for k, v := range target.Data {
		data.Set(k, v)
	}
	data.Set(paramName, payload)

	body := strings.NewReader(data.Encode())
	return target.URL, method, body, "application/x-www-form-urlencoded", nil
}

func buildJSONRequest(target models.ScanTarget, paramName, payload, method string) (string, string, io.Reader, string, error) {
	bodyMap := deepCopyMap(target.JSONBody)
	setNestedValue(bodyMap, paramName, payload)

	raw, err := json.Marshal(bodyMap)
	if err != nil {
		return "", "", nil, "", err
	}

	return target.URL, method, bytes.NewReader(raw), "application/json", nil
}

func deepCopyMap(src map[string]any) map[string]any {
	dst := make(map[string]any, len(src))
	for k, v := range src {
		switch val := v.(type) {
		case map[string]any:
			dst[k] = deepCopyMap(val)
		default:
			dst[k] = v
		}
	}
	return dst
}

func setNestedValue(m map[string]any, key, value string) {
	if strings.Contains(key, ".") {
		parts := strings.SplitN(key, ".", 2)
		sub, ok := m[parts[0]].(map[string]any)
		if !ok {
			sub = make(map[string]any)
			m[parts[0]] = sub
		}
		setNestedValue(sub, parts[1], value)
		return
	}
	m[key] = value
}
