package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const ddgSearchURL = "https://html.duckduckgo.com/html/"

var reDDGUddg = regexp.MustCompile(`uddg=([^&"']+)`)

// ddgClient collecte via DuckDuckGo HTML (souvent OK sur VPS, Bing = captcha).
type ddgClient struct {
	http    *http.Client
	delay   time.Duration
	daySeed int
}

func newDDGClient(daySeed int) *ddgClient {
	return &ddgClient{
		http:    newDiscoverHTTPClient(false),
		delay:   2 * time.Second,
		daySeed: daySeed,
	}
}

func (d *ddgClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), d.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}

	dork := dorks[absolutePage%len(dorks)]
	depth := absolutePage / len(dorks)
	offset := depth * 30

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(d.delay):
	}

	return d.search(ctx, dork, offset)
}

func (d *ddgClient) search(ctx context.Context, query string, offset int) ([]string, error) {
	u, err := url.Parse(ddgSearchURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	if offset > 0 {
		q.Set("s", fmt.Sprintf("%d", offset))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9")

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ddg HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	return filterSwissURLs(parseDDGResults(string(body))), nil
}

func parseDDGResults(html string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}

	for _, m := range reDDGUddg.FindAllStringSubmatch(html, -1) {
		decoded, err := url.QueryUnescape(m[1])
		if err != nil {
			continue
		}
		add(decoded)
	}
	return out
}
