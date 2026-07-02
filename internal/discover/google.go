package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	googleSearchURL = "https://www.google.com/search"
	googleMaxRetry  = 8
)

// googleClient : SerpAPI si clé configurée, sinon scraping Google via proxy BP.
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
	if UseSerpAPI() {
		return g.fetchSerpAPI(ctx, domain, subs, absolutePage)
	}
	if !HasDiscoverProxy() {
		return nil, fmt.Errorf("google: configure DISCOVER_PROXY dans sqli-hunter.env (proxy BP résidentiel)")
	}
	return g.fetchHTML(ctx, domain, subs, absolutePage)
}

func (g *googleClient) fetchSerpAPI(ctx context.Context, domain string, subs bool, absolutePage int) ([]string, error) {
	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), g.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}
	dork := dorks[absolutePage%len(dorks)]
	start := (absolutePage / len(dorks)) * 50

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(g.delay):
	}
	return g.searchSerpAPI(ctx, dork, start)
}

func (g *googleClient) fetchHTML(ctx context.Context, domain string, subs bool, absolutePage int) ([]string, error) {
	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), g.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}
	dork := dorks[absolutePage%len(dorks)]
	start := (absolutePage / len(dorks)) * 50

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(g.delay):
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
		// Nouveau client à chaque essai → nouvelle IP via proxy BP rotatif.
		urls, err := g.searchHTML(ctx, dork, start)
		if err != nil {
			lastErr = err
			continue
		}
		if len(urls) > 0 {
			return urls, nil
		}
		lastErr = fmt.Errorf("google: page vide (essai %d/%d)", attempt+1, googleMaxRetry)
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

	client := &http.Client{
		Timeout:   searchHTTPTimeout,
		Transport: newProxyTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

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
		return nil, fmt.Errorf("google: captcha/blocage (nouvelle IP au prochain essai)")
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
