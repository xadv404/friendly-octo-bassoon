package discover

import "context"

type searchBackend int

const (
	backendDDG searchBackend = iota
	backendGoogle
	backendBing
)

// autoFetcher : DDG (gratuit VPS) → Google (proxies) → Bing.
type autoFetcher struct {
	ddg     *ddgClient
	google  *googleClient
	bing    *bingClient
	backend searchBackend
}

func newAutoFetcher(daySeed int) *autoFetcher {
	backend := backendDDG
	if globalProxyPool.hasProxies() {
		backend = backendGoogle
	}
	return &autoFetcher{
		ddg:     newDDGClient(daySeed),
		google:  newGoogleClient(daySeed),
		bing:    newBingClient(daySeed),
		backend: backend,
	}
}

func (a *autoFetcher) FetchPage(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	for tries := 0; tries < 3; tries++ {
		urls, err := a.fetchCurrent(ctx, domain, subs, absolutePage, limit)
		if err == nil && len(urls) > 0 {
			return urls, nil
		}
		a.advance()
	}
	return a.fetchCurrent(ctx, domain, subs, absolutePage, limit)
}

func (a *autoFetcher) fetchCurrent(ctx context.Context, domain string, subs bool, absolutePage, limit int) ([]string, error) {
	switch a.backend {
	case backendGoogle:
		if globalProxyPool.hasProxies() {
			return a.google.FetchPage(ctx, domain, subs, absolutePage, limit)
		}
		a.advance()
		return a.fetchCurrent(ctx, domain, subs, absolutePage, limit)
	case backendBing:
		return a.bing.FetchPage(ctx, domain, subs, absolutePage, limit)
	default:
		return a.ddg.FetchPage(ctx, domain, subs, absolutePage, limit)
	}
}

func (a *autoFetcher) advance() {
	switch a.backend {
	case backendDDG:
		if globalProxyPool.hasProxies() {
			a.backend = backendGoogle
		} else {
			a.backend = backendBing
		}
	case backendGoogle:
		a.backend = backendBing
	default:
		a.backend = backendDDG
	}
}
