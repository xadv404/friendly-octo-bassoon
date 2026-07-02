package discover

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

// googleClient scrape Google direct via proxy BP (TLS + headless).
type googleClient struct {
	delay   time.Duration
	daySeed int
}

func newGoogleClient(daySeed int) *googleClient {
	return &googleClient{
		delay:   1500 * time.Millisecond,
		daySeed: daySeed,
	}
}

func (g *googleClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	if !HasDiscoverProxy() {
		return nil, fmt.Errorf("google: configure DISCOVER_PROXY dans sqli-hunter.env (proxy BP résidentiel)")
	}
	return g.fetchDirect(ctx, domain, subs, absolutePage)
}

func (g *googleClient) fetchDirect(ctx context.Context, domain string, subs bool, absolutePage int) ([]string, error) {
	dorks := DailyDorkOrder(BuildVulnDorks(domain, subs), g.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}
	dork := dorks[absolutePage%len(dorks)]
	start := (absolutePage / len(dorks)) * googleResultsNum

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(googleJitter(g.delay)):
	}

	var lastErr error
	for attempt := 0; attempt < googleMaxRetry; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(googleRetryDelay(attempt)):
			}
		}

		if urls, err := g.attemptDirect(ctx, dork, start, attempt); len(urls) > 0 {
			return urls, nil
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("google: page vide (essai %d/%d)", attempt+1, googleMaxRetry)
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, nil
}

func (g *googleClient) attemptDirect(ctx context.Context, query string, start, attempt int) ([]string, error) {
	// 1) HTTP/TLS rapide (même IP pour toute la session)
	client, err := newGoogleTLSClient(attempt)
	if err == nil {
		if attempt > 0 {
			resetGoogleTLSProxy(client)
		}
		if urls, err := g.searchTLS(ctx, client, query, start); len(urls) > 0 {
			return urls, nil
		} else if err != nil && !isGoogleRetryable(err) {
			return nil, err
		}
	}

	// 2) Chromium headless direct (JS + consent clic)
	urls, err := googleHeadlessFetch(ctx, query, start, attempt)
	if len(urls) > 0 {
		return urls, nil
	}
	return nil, err
}

func (g *googleClient) searchTLS(ctx context.Context, client tls_client.HttpClient, query string, start int) ([]string, error) {
	if err := googleTLSWarmUp(ctx, client); err != nil {
		return nil, err
	}

	referer := googleHomeURL
	strategies := googleSearchStrategies()
	var lastErr error

	for i, strat := range strategies {
		searchURL, err := buildGoogleSearchURL(strat, query, start)
		if err != nil {
			lastErr = err
			continue
		}

		if i == 0 {
			if body, err := tryGoogleConsentDL(ctx, client, searchURL, referer); err == nil && len(parseGoogleResults(body)) > 0 {
				urls := filterSwissURLs(parseGoogleResults(body))
				if len(urls) > 0 {
					return urls, nil
				}
			}
		}

		urls, html, err := g.doGoogleSearch(ctx, client, strat, query, start, referer)
		if err != nil {
			lastErr = err
			if strings.Contains(err.Error(), "429") || strings.Contains(err.Error(), "sorry") {
				break
			}
			continue
		}

		if isGoogleConsentPage(html) {
			html, err = acceptGoogleConsent(ctx, client, html, searchURL)
			if err != nil {
				lastErr = err
				continue
			}
			urls = filterSwissURLs(parseGoogleResults(html))
		}

		if len(urls) > 0 {
			return urls, nil
		}

		if isGoogleEnableJS(html) {
			html2, err := followGoogleEnableJS(ctx, client, html, searchURL, referer)
			if err == nil {
				urls = filterSwissURLs(parseGoogleResults(html2))
				if len(urls) > 0 {
					return urls, nil
				}
			}
			lastErr = fmt.Errorf("google: enablejs (%s)", strat.label)
			continue
		}

		if isGoogleHardBlocked(html) {
			lastErr = fmt.Errorf("google: blocage (%s)", strat.label)
			break
		}
		lastErr = fmt.Errorf("google: vide (%s)", strat.label)
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
	if len(html) < 400 {
		return nil, html, fmt.Errorf("google: réponse trop courte")
	}
	if strings.Contains(html, "/sorry") {
		return nil, html, fmt.Errorf("google: sorry")
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
	q.Set("pws", "0")
	for k, v := range strat.params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
