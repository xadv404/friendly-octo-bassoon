package discover

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	bingSearchURL = "https://www.bing.com/search"
)

var (
	reBingHref = regexp.MustCompile(`(?i)<a[^>]+href="([^"]+)"`)
	reBingCite = regexp.MustCompile(`(?i)<cite[^>]*>([^<]+)</cite>`)
	reBingSkip = regexp.MustCompile(`(?i)(bing\.com|microsoft\.com|msn\.com|live\.com)`)
)

// bingClient collecte des URLs via Bing (proxyless).
type bingClient struct {
	http    *http.Client
	delay   time.Duration
	baseURL string
	daySeed int
}

func newBingClient(daySeed int) *bingClient {
	return &bingClient{
		http:    newDiscoverHTTPClient(false),
		delay:   2 * time.Second,
		daySeed: daySeed,
	}
}

// FetchPage exécute un dork Bing (absolutePage = curseur global + offset run).
func (b *bingClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), b.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}

	dork := dorks[absolutePage%len(dorks)]
	depth := absolutePage / len(dorks)
	bingFirst := depth*50 + 1

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(b.delay):
	}

	return b.search(ctx, dork, bingFirst)
}

func (b *bingClient) search(ctx context.Context, query string, first int) ([]string, error) {
	urls, blocked, err := b.searchRaw(ctx, query, first)
	if err != nil {
		return nil, err
	}
	if blocked {
		return nil, nil
	}
	return filterSwissURLs(urls), nil
}

func (b *bingClient) searchRaw(ctx context.Context, query string, first int) ([]string, bool, error) {
	base := b.baseURL
	if base == "" {
		base = bingSearchURL
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, false, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("count", "50")
	q.Set("first", fmt.Sprintf("%d", first))
	q.Set("setlang", "fr-CH")
	q.Set("cc", "CH")
	q.Set("setmkt", "fr-CH")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9,de-CH;q=0.8")

	resp, err := b.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("bing HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, false, err
	}

	html := string(body)
	if isBingBlocked(html) {
		return nil, true, nil
	}
	return parseBingResults(html), false, nil
}

func filterSwissURLs(urls []string) []string {
	if len(urls) == 0 {
		return urls
	}
	out := make([]string, 0, len(urls))
	seen := make(map[string]struct{}, len(urls))
	for _, raw := range urls {
		if !IsSwissURL(raw) {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}
	return out
}

func parseBingResults(html string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		if strings.HasPrefix(raw, "/") {
			raw = "https://www.bing.com" + raw
		}
		raw = unwrapBingRedirect(raw)
		if raw == "" || reBingSkip.MatchString(raw) {
			return
		}
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			if strings.Contains(raw, ".") {
				raw = "https://" + raw
			} else {
				return
			}
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}

	for _, m := range reBingHref.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reBingCite.FindAllStringSubmatch(html, -1) {
		cite := strings.TrimSpace(m[1])
		cite = strings.TrimPrefix(cite, "https://")
		cite = strings.TrimPrefix(cite, "http://")
		cite = strings.TrimSuffix(cite, " › …")
		cite = strings.TrimSuffix(cite, " ...")
		if strings.Contains(cite, " ") {
			cite = strings.Fields(cite)[0]
		}
		add(cite)
	}

	return out
}

func unwrapBingRedirect(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if !strings.Contains(u.Host, "bing.com") {
		return raw
	}
	if enc := u.Query().Get("u"); enc != "" {
		if decoded, err := decodeBingURL(enc); err == nil && decoded != "" {
			return decoded
		}
	}
	return ""
}

func decodeBingURL(enc string) (string, error) {
	if strings.HasPrefix(enc, "a1") {
		enc = enc[2:]
	}
	enc = strings.ReplaceAll(enc, "-", "+")
	enc = strings.ReplaceAll(enc, "_", "/")
	for len(enc)%4 != 0 {
		enc += "="
	}
	b, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func defaultFetcher(source Source, daySeed int) CDXFetcher {
	switch source {
	case SourceWayback:
		return newWaybackClient()
	case SourceGoogle:
		return newGoogleClient(daySeed)
	case SourceDDG:
		return newDDGClient(daySeed)
	case SourceAuto:
		return newAutoFetcher(daySeed)
	default:
		return newBingClient(daySeed)
	}
}
