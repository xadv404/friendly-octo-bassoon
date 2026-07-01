package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const waybackCDX = "https://web.archive.org/cdx/search/cdx"

// waybackClient interroge l'API CDX Internet Archive.
type waybackClient struct {
	http    *http.Client
	baseURL string
}

func newWaybackClient() *waybackClient {
	return &waybackClient{
		baseURL: waybackCDX,
		http: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (w *waybackClient) FetchPage(ctx context.Context, domain string, subs bool, page, limit int) ([]string, error) {
	pattern := domain + "/*"
	if subs {
		pattern = "*." + domain + "/*"
	}

	q := url.Values{}
	q.Set("url", pattern)
	q.Set("output", "json")
	q.Set("fl", "original")
	q.Set("collapse", "urlkey")
	q.Set("filter", "statuscode:200")
	q.Set("limit", strconv.Itoa(limit))
	q.Set("page", strconv.Itoa(page))

	reqURL := w.baseURL + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sqli-hunter/1.8 discover")

	resp, err := w.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wayback: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("wayback HTTP %d: %s", resp.StatusCode, string(body))
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return nil, fmt.Errorf("wayback JSON: %w", err)
	}
	if len(rows) <= 1 {
		return nil, nil
	}

	urls := make([]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		if len(row) > 0 && row[0] != "" {
			urls = append(urls, row[0])
		}
	}
	return urls, nil
}
