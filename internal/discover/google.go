package discover

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

const (
	googleHomeURL    = "https://www.google.ch/"
	googleMaxRetry   = 12
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
		// Essai rapide HTTP/TLS (gbv=1), puis headless Chromium si enablejs.
		client, err := newGoogleTLSClient()
		if err != nil {
			lastErr = err
		} else {
			if attempt > 0 {
				resetGoogleTLSProxy(client)
			}
			urls, err := g.searchHTML(ctx, client, dork, start)
		if err != nil {
				lastErr = err
			} else if len(urls) > 0 {
				return urls, nil
			}
		}

		urls, err := googleHeadlessFetch(ctx, dork, start)
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
			baseURL: "https://www.google.com/search",
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
	}
}

func (g *googleClient) searchHTML(ctx context.Context, client tls_client.HttpClient, query string, start int) ([]string, error) {
	if err := googleTLSWarmUp(ctx, client); err != nil {
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
		if isGoogleConsentPage(html) {
			html, err = acceptGoogleConsent(ctx, client, html, strat.baseURL)
			if err != nil {
				lastErr = err
				continue
			}
			urls = filterSwissURLs(parseGoogleResults(html))
		}
		if len(urls) > 0 {
			return urls, nil
		}
		if isGoogleHardBlocked(html) {
			lastErr = fmt.Errorf("google: captcha/blocage")
			continue
		}
		if isGoogleEnableJS(html) {
			lastErr = fmt.Errorf("google: enablejs")
			continue
		}
		lastErr = fmt.Errorf("google: page vide")
	}
	return nil, lastErr
}

func (g *googleClient) doGoogleSearch(ctx context.Context, client tls_client.HttpClient, strat googleSearchStrategy, query string, start int, referer string) ([]string, string, error) {
	searchURL, err := buildGoogleSearchURL(strat, query, start)
	if err != nil {
		return nil, "", err
	}

	html, code, err := googleTLSGet(ctx, client, searchURL, referer)
	if err != nil {
		return nil, "", err
	}
	if code == 429 {
		return nil, html, fmt.Errorf("google HTTP 429")
	}
	if code != 200 {
		return nil, html, fmt.Errorf("google HTTP %d", code)
	}
	if len(html) < 500 {
		return nil, html, fmt.Errorf("google: réponse trop courte")
	}
	if strings.Contains(html, "/sorry") {
		return nil, html, fmt.Errorf("google: sorry redirect")
	}

	return filterSwissURLs(parseGoogleResults(html)), html, nil
}

func buildGoogleSearchURL(strat googleSearchStrategy, query string, start int) (string, error) {
	u, err := url.Parse(strat.baseURL)
	if err != nil {
		return "", err
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
	return u.String(), nil
}
