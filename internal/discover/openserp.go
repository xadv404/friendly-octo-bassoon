package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	openSerpDefaultBase = "https://api.openserp.dev"
	openSerpEngine      = "google_search"
	openSerpMaxResults  = 10
	openSerpMaxRetry    = 3
)

// openSerpResponse — format documenté sur https://openserp.dev/docs
type openSerpResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Data    struct {
		Results []openSerpResult `json:"results"`
	} `json:"data"`
}

type openSerpResult struct {
	Position int    `json:"position"`
	Title    string `json:"title"`
	Link     string `json:"link"`
	Snippet  string `json:"snippet"`
}

func openSerpAPIKey() string {
	return strings.TrimSpace(os.Getenv("OPENSERP_API_KEY"))
}

func openSerpBaseURL() string {
	if v := strings.TrimSpace(os.Getenv("OPENSERP_API_URL")); v != "" {
		return strings.TrimRight(v, "/")
	}
	return openSerpDefaultBase
}

// UseOpenSerp indique si la clé OpenSerp est configurée.
func UseOpenSerp() bool {
	return openSerpAPIKey() != ""
}

func openSerpJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return base/2 + time.Duration(time.Now().UnixNano()%int64(base/2+1))
}

func (g *googleClient) fetchOpenSerp(ctx context.Context, domain string, subs bool, absolutePage int) ([]string, error) {
	dorks := OrderedDorks(g.dorkSet, domain, subs, g.daySeed)
	if len(dorks) == 0 {
		return nil, nil
	}
	dork := dorks[absolutePage%len(dorks)]
	start := (absolutePage / len(dorks)) * openSerpMaxResults

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(openSerpJitter(g.delay)):
	}

	var lastErr error
	for attempt := 0; attempt < openSerpMaxRetry; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(openSerpJitter(time.Duration(attempt+1) * time.Second)):
			}
		}
		urls, err := g.searchOpenSerp(ctx, dork, start, !IsSwissWide(domain))
		if len(urls) > 0 {
			return urls, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func (g *googleClient) searchOpenSerp(ctx context.Context, query string, start int, requireCHHost bool) ([]string, error) {
	key := openSerpAPIKey()
	if key == "" {
		return nil, fmt.Errorf("openserp: OPENSERP_API_KEY manquant")
	}

	u, err := url.Parse(openSerpBaseURL() + "/v1/search")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("engine", openSerpEngine)
	q.Set("language", "fr")
	q.Set("country", "CH")
	if start > 0 {
		q.Set("start", fmt.Sprintf("%d", start))
	}
	q.Set("num", fmt.Sprintf("%d", openSerpMaxResults))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", key)

	resp, err := (&http.Client{Timeout: searchHTTPTimeout}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("openserp: clé API invalide")
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable {
		return nil, fmt.Errorf("openserp HTTP %d", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openserp HTTP %d: %s", resp.StatusCode, truncateErrBody(body))
	}

	var parsed openSerpResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("openserp JSON: %w", err)
	}
	if !parsed.Success {
		if parsed.Error != "" {
			return nil, fmt.Errorf("openserp: %s", parsed.Error)
		}
		return nil, fmt.Errorf("openserp: requête échouée")
	}

	urls := filterDiscoveryURLs(parseOpenSerpResults(parsed), requireCHHost)
	return urls, nil
}

func parseOpenSerpResults(resp openSerpResponse) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, item := range resp.Data.Results {
		raw := strings.TrimSpace(item.Link)
		if raw == "" {
			continue
		}
		if reGoogleSkip.MatchString(raw) {
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
