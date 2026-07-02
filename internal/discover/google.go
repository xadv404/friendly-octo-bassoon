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

const googleSearchURL = "https://www.google.com/search"

var (
	reGoogleURL  = regexp.MustCompile(`(?i)/url\?q=([^&"']+)`)
	reGoogleSkip = regexp.MustCompile(`(?i)(google\.|gstatic\.com|youtube\.com|webcache)`)
)

// googleClient collecte via Google Search (proxy rotatif recommandé).
type googleClient struct {
	http    *http.Client
	delay   time.Duration
	daySeed int
}

func newGoogleClient(daySeed int) *googleClient {
	return &googleClient{
		http:    newDiscoverHTTPClient(),
		delay:   3 * time.Second,
		daySeed: daySeed,
	}
}

func (g *googleClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	if !getProxyPool().hasProxies() {
		return nil, fmt.Errorf("google: configure DISCOVER_PROXY dans sqli-hunter.env")
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

	return g.search(ctx, dork, start)
}

func (g *googleClient) search(ctx context.Context, query string, start int) ([]string, error) {
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
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9")

	resp, err := g.http.Do(req)
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
	if isGoogleBlocked(html) {
		return nil, fmt.Errorf("google: captcha/blocage (change de proxy)")
	}

	return filterSwissURLs(parseGoogleResults(html)), nil
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
	return out
}
