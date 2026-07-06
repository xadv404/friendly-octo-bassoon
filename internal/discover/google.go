package discover

import (
	"context"
	"fmt"
	"time"
)

// googleClient interroge Google via OpenSerp API uniquement.
type googleClient struct {
	delay   time.Duration
	daySeed int
	dorkSet DorkSet
}

func newGoogleClient(daySeed int, dorkSet DorkSet) *googleClient {
	return &googleClient{
		delay:   1500 * time.Millisecond,
		daySeed: daySeed,
		dorkSet: dorkSet,
	}
}

func (g *googleClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	if !UseOpenSerp() {
		return nil, fmt.Errorf("google: configure OPENSERP_API_KEY dans sqli-hunter.env")
	}
	return g.fetchOpenSerp(ctx, domain, subs, absolutePage)
}

func (g *googleClient) FetchDork(ctx context.Context, dork string, start int) ([]string, error) {
	if !UseOpenSerp() {
		return nil, fmt.Errorf("google: configure OPENSERP_API_KEY dans sqli-hunter.env")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(openSerpJitter(g.delay)):
	}
	return g.searchOpenSerp(ctx, dork, start, false)
}
