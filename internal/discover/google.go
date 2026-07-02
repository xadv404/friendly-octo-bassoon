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
}

func newGoogleClient(daySeed int) *googleClient {
	return &googleClient{
		delay:   1500 * time.Millisecond,
		daySeed: daySeed,
	}
}

func (g *googleClient) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	if !UseOpenSerp() {
		return nil, fmt.Errorf("google: configure OPENSERP_API_KEY dans sqli-hunter.env")
	}
	return g.fetchOpenSerp(ctx, domain, subs, absolutePage)
}
