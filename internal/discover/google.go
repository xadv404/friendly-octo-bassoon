package discover

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

const (
	googleHomeURL   = "https://www.google.ch/"
	googleMaxRetry  = 8
	googleResultsNum = 10
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
	start := (absolutePage / len(dorks)) * googleResultsNum

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
	start := (absolutePage / len(dorks)) * googleResultsNum

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
			case <-time.After(time.Duration(attempt*2) * time.Second):
			}
		}
		// Un client par essai (cookie jar + même IP proxy pour warmup + recherche).
		client := newGoogleHTTPClient()
		urls, err := g.searchHTML(ctx, client, dork, start)
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

func newGoogleHTTPClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:   searchHTTPTimeout,
		Transport: newProxyTransport(),
		Jar:       jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if strings.Contains(req.URL.String(), "/sorry") {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

type googleSearchStrategy struct {
	baseURL string
	params  map[string]string
}

func googleSearchStrategies() []googleSearchStrategy {
	return []googleSearchStrategy{
		{
			baseURL: "https://www.google.ch/search",
			params: map[string]string{
				"gbv": "1",
				"udm": "14",
			},
		},
		{
			baseURL: "https://www.google.ch/search",
			params: map[string]string{
				"gbv": "2",
			},
		},
		{
			baseURL: "https://www.google.com/search",
			params: map[string]string{
				"gbv": "1",
				"udm": "14",
			},
		},
	}
}

func (g *googleClient) searchHTML(ctx context.Context, client *http.Client, query string, start int) ([]string, error) {
	if err := warmUpGoogle(ctx, client); err != nil {
		return nil, fmt.Errorf("google warmup: %w", err)
	}

	referer := googleHomeURL
	var lastErr error
	for _, strat := range googleSearchStrategies() {
		urls, html, err := g.doGoogleSearch(ctx, client, strat, query, start, referer)
		if err != nil {
			lastErr = err
			continue
		}
		if len(urls) > 0 {
			return urls, nil
		}
		if isGoogleHardBlocked(html) {
			lastErr = fmt.Errorf("google: captcha/blocage")
			continue
		}
		if isGoogleEnableJS(html) {
			lastErr = fmt.Errorf("google: enablejs (stratégie %s)", strat.baseURL)
			continue
		}
		lastErr = fmt.Errorf("google: page vide")
	}
	return nil, lastErr
}

func warmUpGoogle(ctx context.Context, client *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleHomeURL, nil)
	if err != nil {
		return err
	}
	setGoogleHeaders(req, "")
	req.AddCookie(&http.Cookie{Name: "CONSENT", Value: googleConsentCookie})

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(400 * time.Millisecond):
	}
	return nil
}

func (g *googleClient) doGoogleSearch(ctx context.Context, client *http.Client, strat googleSearchStrategy, query string, start int, referer string) ([]string, string, error) {
	u, err := url.Parse(strat.baseURL)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("num", fmt.Sprintf("%d", googleResultsNum))
	if start > 0 {
		q.Set("start", fmt.Sprintf("%d", start))
	}
	q.Set("hl", "fr")
	q.Set("gl", "ch")
	q.Set("cr", "countryCH")
	for k, v := range strat.params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	setGoogleHeaders(req, referer)
	req.AddCookie(&http.Cookie{Name: "CONSENT", Value: googleConsentCookie})

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, "", fmt.Errorf("google HTTP 429")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("google HTTP %d", resp.StatusCode)
	}
	if strings.Contains(resp.Request.URL.String(), "/sorry") {
		return nil, "", fmt.Errorf("google: sorry redirect")
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, "", err
	}
	html := string(body)
	if len(html) < 500 {
		return nil, html, fmt.Errorf("google: réponse trop courte")
	}

	return filterSwissURLs(parseGoogleResults(html)), html, nil
}

const googleConsentCookie = "YES+cb.20210720-07-p0.fr+FX+667"

func setGoogleHeaders(req *http.Request, referer string) {
	req.Header.Set("User-Agent", searchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "fr-CH,fr;q=0.9,de-CH;q=0.8,de;q=0.7,en;q=0.4")
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Sec-CH-UA", `"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", `"Windows"`)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	if referer == "" {
		req.Header.Set("Sec-Fetch-Site", "none")
	} else {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Referer", referer)
	}
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
}
