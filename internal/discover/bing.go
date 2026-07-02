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
	bingUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)

var (
	reBingHref  = regexp.MustCompile(`(?i)<a[^>]+href="([^"]+)"`)
	reBingCite  = regexp.MustCompile(`(?i)<cite[^>]*>([^<]+)</cite>`)
	reBingSkip  = regexp.MustCompile(`(?i)(bing\.com|microsoft\.com|msn\.com|live\.com)`)
)

// bingClient collecte des URLs via Bing (proxyless).
type bingClient struct {
	http    *http.Client
	delay   time.Duration
	baseURL string
}

func newBingClient() *bingClient {
	return &bingClient{
		http: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("trop de redirections")
				}
				return nil
			},
		},
		delay: 2 * time.Second,
	}
}

// FetchPage exécute un dork Bing (page = rotation dork + offset résultats).
func (b *bingClient) FetchPage(ctx context.Context, domain string, subs bool, page, limit int) ([]string, error) {
	dorks := BuildEmailDorks(domain, subs)
	if len(dorks) == 0 {
		return nil, nil
	}

	dork := dorks[page%len(dorks)]
	bingFirst := (page/len(dorks))*10 + 1

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(b.delay):
	}

	return b.search(ctx, dork, bingFirst)
}

func (b *bingClient) search(ctx context.Context, query string, first int) ([]string, error) {
	base := b.baseURL
	if base == "" {
		base = bingSearchURL
	}

	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("count", "50")
	q.Set("first", fmt.Sprintf("%d", first))
	q.Set("setlang", "fr")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", bingUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9")

	resp, err := b.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bing HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, err
	}

	return parseBingResults(string(body)), nil
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

func defaultFetcher(source Source) CDXFetcher {
	switch source {
	case SourceWayback:
		return newWaybackClient()
	default:
		return newBingClient()
	}
}
