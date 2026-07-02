package discover

import "context"
// autoFetcher délègue à DuckDuckGo (proxyless).
type autoFetcher struct {
	ddg *ddgClient
}

func newAutoFetcher(daySeed int) *autoFetcher {
	return &autoFetcher{ddg: newDDGClient(daySeed)}
}

func (a *autoFetcher) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	return a.ddg.FetchPage(ctx, domain, subs, absolutePage, limit)
}
