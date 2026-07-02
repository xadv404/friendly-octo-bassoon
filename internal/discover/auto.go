package discover

import "context"

// autoFetcher = Google via OpenSerp API.
type autoFetcher struct {
	google *googleClient
}

func newAutoFetcher(daySeed int) *autoFetcher {
	return &autoFetcher{google: newGoogleClient(daySeed)}
}

func (a *autoFetcher) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	return a.google.FetchPage(ctx, domain, subs, absolutePage, limit)
}

func (a *autoFetcher) FetchDork(ctx context.Context, dork string, start int) ([]string, error) {
	return a.google.FetchDork(ctx, dork, start)
}
