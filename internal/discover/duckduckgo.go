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

// ddgClient collecte via DuckDuckGo HTML (proxyless).
type ddgClient struct {
	http    *http.Client
	delay   time.Duration
	daySeed int
}

func newDDGClient(daySeed int) *ddgClient {
	return &ddgClient{
		http:    newDirectHTTPClient(),
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
	form := url.Values{}
	form.Set("q", query)
	if offset > 0 {
		form.Set("s", fmt.Sprintf("%d", offset))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ddgSearchURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9,de-CH;q=0.8")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("ddg HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	html := string(body)
	if isDDGBlocked(html) {
		return nil, fmt.Errorf("ddg: captcha/anomalie bot détectée")
	}

	urls := filterSwissURLs(parseDDGResults(html))
	if len(urls) == 0 && !strings.Contains(html, "result__body") {
		return nil, fmt.Errorf("ddg: aucun résultat (page vide ou bloquée)")
	}
	return urls, nil
}

func isDDGBlocked(html string) bool {
	lower := strings.ToLower(html)
	for _, marker := range []string{
		"anomaly-modal",
		"bots use duckduckgo",
		"challenge-form",
		"confirm this search was made by a human",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return isSearchBlocked(html)
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
