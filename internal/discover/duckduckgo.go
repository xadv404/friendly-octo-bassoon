package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	ddgSearchURL   = "https://html.duckduckgo.com/html/"
	ddgMaxRetry    = 3
	ddgResultsStep = 30
)

var (
	reDDGUddg        = regexp.MustCompile(`(?i)uddg=([^&"']+)`)
	reDDGVQD         = regexp.MustCompile(`name="vqd"\s+value="([^"]+)"`)
	reDDGResultLink  = regexp.MustCompile(`(?i)class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"`)
	reDDGWebResult   = regexp.MustCompile(`(?i)class="[^"]*web-result[^"]*"`)
)

var globalVQDCache = &vqdCache{data: make(map[string]string)}

type vqdCache struct {
	mu   sync.RWMutex
	data map[string]string
}

func (c *vqdCache) Get(query string) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data[vqdKey(query)]
}

func (c *vqdCache) Set(query, vqd string) {
	if vqd == "" {
		return
	}
	c.mu.Lock()
	c.data[vqdKey(query)] = vqd
	c.mu.Unlock()
}

func vqdKey(query string) string {
	return query + "|" + searchUserAgent
}

// ddgClient scrape DuckDuckGo HTML (html.duckduckgo.com).
type ddgClient struct {
	delay   time.Duration
	daySeed int
}

func newDDGClient(daySeed int) *ddgClient {
	return &ddgClient{
		delay:   2 * time.Second,
		daySeed: daySeed,
	}
}

func (d *ddgClient) FetchDork(ctx context.Context, dork string, start int) ([]string, error) {
	offset := 0
	if start > 0 {
		offset = 10 + (start-1)*15
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(d.delay):
	}
	client := newDDGHTTPClient()
	return d.search(ctx, client, dork, offset)
}

func (d *ddgClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), d.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}

	dork := dorks[absolutePage%len(dorks)]
	depth := absolutePage / len(dorks)
	offset := 0
	if depth > 0 {
		offset = 10 + (depth-1)*15
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(d.delay):
	}

	var lastErr error
	for attempt := 0; attempt < ddgMaxRetry; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}

		client := newDDGHTTPClient()
		urls, err := d.search(ctx, client, dork, offset)
		if err != nil {
			lastErr = err
			continue
		}
		if len(urls) > 0 {
			return urls, nil
		}
		lastErr = fmt.Errorf("ddg: page vide (essai %d/%d)", attempt+1, ddgMaxRetry)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func newDDGHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   searchHTTPTimeout,
		Transport: newProxyTransport(),
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (d *ddgClient) search(ctx context.Context, client *http.Client, query string, offset int) ([]string, error) {
	if err := d.warmUp(ctx, client); err != nil {
		return nil, err
	}

	vqd := globalVQDCache.Get(query)
	if offset > 0 && vqd == "" {
		// Récupère vqd via une première page avant pagination.
		if _, err := d.postSearch(ctx, client, query, 0, ""); err != nil {
			return nil, err
		}
		vqd = globalVQDCache.Get(query)
		if vqd == "" {
			return nil, fmt.Errorf("ddg: vqd manquant pour pagination")
		}
	}

	html, err := d.postSearch(ctx, client, query, offset, vqd)
	if err != nil {
		return nil, err
	}

	if isDDGBlocked(html) {
		return nil, fmt.Errorf("ddg: captcha/anomalie bot")
	}

	if v := parseVQD(html); v != "" {
		globalVQDCache.Set(query, v)
	}

	urls := filterSwissURLs(parseDDGResults(html))
	if len(urls) == 0 && !reDDGWebResult.MatchString(html) && !strings.Contains(html, "result__body") {
		return nil, fmt.Errorf("ddg: aucun résultat")
	}
	return urls, nil
}

func (d *ddgClient) warmUp(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ddgSearchURL, nil)
	if err != nil {
		return err
	}
	setDDGHeaders(req, "")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

func (d *ddgClient) postSearch(ctx context.Context, client *http.Client, query string, offset int, vqd string) (string, error) {
	form := buildDDGForm(query, offset, vqd)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ddgSearchURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	setDDGHeaders(req, ddgSearchURL)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("ddg HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func buildDDGForm(query string, offset int, vqd string) url.Values {
	form := url.Values{}
	form.Set("q", query)
	form.Set("kl", "de-ch")

	if offset <= 0 {
		form.Set("b", "")
		return form
	}

	form.Set("vqd", vqd)
	form.Set("nextParams", "")
	form.Set("api", "d.js")
	form.Set("o", "json")
	form.Set("v", "l")
	form.Set("s", fmt.Sprintf("%d", offset))
	form.Set("dc", fmt.Sprintf("%d", offset+1))
	return form
}

func setDDGHeaders(req *http.Request, referer string) {
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "de-CH,de;q=0.9,fr-CH;q=0.8,fr;q=0.7")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Origin", "https://html.duckduckgo.com")
	if referer == "" {
		referer = "https://html.duckduckgo.com/"
	}
	req.Header.Set("Referer", referer)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	if req.Method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
}

func parseVQD(html string) string {
	if m := reDDGVQD.FindStringSubmatch(html); len(m) > 1 {
		return m[1]
	}
	return ""
}

func isDDGBlocked(html string) bool {
	lower := strings.ToLower(html)
	for _, marker := range []string{
		"anomaly-modal",
		"bots use duckduckgo",
		"challenge-form",
		"confirm this search was made by a human",
		"id=\"challenge-form\"",
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
		if strings.HasPrefix(raw, "//") {
			raw = "https:" + raw
		}
		if u := unwrapDDGLink(raw); u != "" {
			raw = u
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

	for _, m := range reDDGResultLink.FindAllStringSubmatch(html, -1) {
		add(m[1])
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

func unwrapDDGLink(raw string) string {
	if !strings.Contains(raw, "uddg=") {
		if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
			return raw
		}
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	uddg := u.Query().Get("uddg")
	if uddg == "" {
		if m := reDDGUddg.FindStringSubmatch(raw); len(m) > 1 {
			uddg = m[1]
		}
	}
	if uddg == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(uddg)
	if err != nil {
		return uddg
	}
	return decoded
}
