package discover

import (
	"context"
	"fmt"
	"time"
)

// googleClient collecte via SerpAPI (google_light).
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
	if !UseSerpAPI() {
		return nil, fmt.Errorf("google: SERPAPI_API_KEY requis dans sqli-hunter.env — https://serpapi.com/manage-api-key")
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

	return g.searchSerpAPI(ctx, dork, start)
}
