package discover

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

// proxyPool rotation round-robin pour DISCOVER_PROXIES / DISCOVER_PROXY.
type proxyPool struct {
	proxies []*url.URL
	seq     atomic.Uint64
}

var globalProxyPool = loadProxyPool()

func loadProxyPool() *proxyPool {
	var raw []string
	if v := strings.TrimSpace(os.Getenv("DISCOVER_PROXIES")); v != "" {
		for _, part := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
			part = strings.TrimSpace(part)
			if part != "" {
				raw = append(raw, part)
			}
		}
	}
	if v := strings.TrimSpace(os.Getenv("DISCOVER_PROXY")); v != "" {
		raw = append(raw, v)
	}

	p := &proxyPool{}
	seen := make(map[string]struct{})
	for _, s := range raw {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			continue
		}
		key := u.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		p.proxies = append(p.proxies, u)
	}
	return p
}

func (p *proxyPool) hasProxies() bool {
	return p != nil && len(p.proxies) > 0
}

func (p *proxyPool) next() *url.URL {
	if !p.hasProxies() {
		return nil
	}
	i := p.seq.Add(1) - 1
	return p.proxies[int(i)%len(p.proxies)]
}

func newDiscoverHTTPClient(rotate bool) *http.Client {
	transport := &http.Transport{}
	if globalProxyPool.hasProxies() {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			if rotate {
				if u := globalProxyPool.next(); u != nil {
					return u, nil
				}
			} else if len(globalProxyPool.proxies) == 1 {
				return globalProxyPool.proxies[0], nil
			} else if u := globalProxyPool.next(); u != nil {
				return u, nil
			}
			return http.ProxyFromEnvironment(req)
		}
	} else {
		transport.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{
		Timeout:   searchHTTPTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
