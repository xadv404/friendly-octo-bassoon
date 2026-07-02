package discover

import "context"

// autoFetcher délègue à Google (proxy BP requis via DISCOVER_PROXY).
type autoFetcher struct {
	google *googleClient
}

func newAutoFetcher(daySeed int) *autoFetcher {
	return &autoFetcher{google: newGoogleClient(daySeed)}
}

func (a *autoFetcher) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	return a.google.FetchPage(ctx, domain, subs, absolutePage, limit)
}
