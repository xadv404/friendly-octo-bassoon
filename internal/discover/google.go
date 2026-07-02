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

const (
	googleSearchURL = "https://www.google.com/search"
	googleMaxRetry  = 8
)

var (
	reGoogleURL      = regexp.MustCompile(`(?i)/url\?q=([^&"']+)`)
	reGoogleDirectCH = regexp.MustCompile(`(?i)https?://[a-zA-Z0-9._\-]+\.ch[^\s"'<>\\]*`)
	reGoogleSkip     = regexp.MustCompile(`(?i)(google\.|gstatic\.com|youtube\.com|webcache)`)
)

// googleClient collecte via SerpAPI (prioritaire) ou Google Search + proxy BP.
type googleClient struct {
	delay   time.Duration
	daySeed int
}

func newGoogleClient(daySeed int) *googleClient {
	return &googleClient{
		delay:   2 * time.Second,
		daySeed: daySeed,
	}
}

func (g *googleClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	if !UseSerpAPI() && !getProxyPool().hasProxies() {
		return nil, fmt.Errorf("google: configure SERPAPI_API_KEY ou DISCOVER_PROXY dans sqli-hunter.env")
	}

	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), g.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}

	dork := dorks[absolutePage%len(dorks)]
	depth := absolutePage / len(dorks)
	start := depth * 50

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(g.delay):
	}

	if UseSerpAPI() {
		return g.searchSerpAPI(ctx, dork, start)
	}

	var lastErr error
	for attempt := 0; attempt < googleMaxRetry; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}

		urls, err := g.searchHTML(ctx, dork, start)
		if err != nil {
			lastErr = err
			continue
		}
		if len(urls) > 0 {
			return urls, nil
		}
		lastErr = fmt.Errorf("google: page vide (retry %d/%d)", attempt+1, googleMaxRetry)
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func (g *googleClient) searchHTML(ctx context.Context, query string, start int) ([]string, error) {
	u, err := url.Parse(googleSearchURL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("num", "50")
	q.Set("start", fmt.Sprintf("%d", start))
	q.Set("hl", "fr")
	q.Set("gl", "ch")
	q.Set("cr", "countryCH")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	setGoogleHeaders(req)

	client := newDiscoverHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}
	html := string(body)
	if len(html) < 1000 || isGoogleBlocked(html) {
		return nil, fmt.Errorf("google: captcha/blocage ou JS requis (nouvelle IP au prochain essai)")
	}

	return filterSwissURLs(parseGoogleResults(html)), nil
}

func setGoogleHeaders(req *http.Request) {
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9,de-CH;q=0.8,de;q=0.7")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.AddCookie(&http.Cookie{Name: "CONSENT", Value: "YES+1"})
}

func parseGoogleResults(html string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		decoded, err := url.QueryUnescape(raw)
		if err == nil && decoded != "" {
			raw = decoded
		}
		raw = strings.TrimRight(raw, `.,;)`)
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			return
		}
		if reGoogleSkip.MatchString(raw) {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}

	for _, m := range reGoogleURL.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	if len(out) == 0 {
		for _, m := range reGoogleDirectCH.FindAllString(html, -1) {
			add(m)
		}
	}
	return out
}
