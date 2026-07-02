package discover

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	proxyMu         sync.RWMutex
	globalProxyPool = &proxyPool{}
)

func init() {
	ReloadProxyPool()
}

// ReloadProxyPool recharge DISCOVER_PROXY après chargement du .env.
func ReloadProxyPool() {
	proxyMu.Lock()
	globalProxyPool = loadProxyPool()
	proxyMu.Unlock()
}

func getProxyPool() *proxyPool {
	proxyMu.RLock()
	p := globalProxyPool
	proxyMu.RUnlock()
	return p
}

// proxyPool — un proxy suffit si l'IP change côté fournisseur (BP Proxy).
type proxyPool struct {
	proxies []*url.URL
}

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
		u, err := parseProxyURL(s)
		if err != nil || u == nil || u.Host == "" {
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

// parseProxyURL accepte http://user:pass@host:port et http://user:pass:host:port (BP Proxy).
func parseProxyURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("proxy vide")
	}

	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		if strings.Contains(raw, "@") || !strings.HasSuffix(strings.SplitN(u.Host, "@", 2)[len(strings.Split(u.Host, "@"))-1], ":") {
			// standard user:pass@host:port
			if u.User != nil || strings.Contains(u.Host, "@") {
				return u, nil
			}
		}
	}

	// http://user:pass:host:port
	scheme := "http"
	rest := raw
	if strings.HasPrefix(rest, "https://") {
		scheme = "https"
		rest = strings.TrimPrefix(rest, "https://")
	} else if strings.HasPrefix(rest, "http://") {
		rest = strings.TrimPrefix(rest, "http://")
	}

	parts := strings.Split(rest, ":")
	if len(parts) == 4 {
		user, pass, host, port := parts[0], parts[1], parts[2], parts[3]
		return url.Parse(fmt.Sprintf("%s://%s:%s@%s:%s", scheme, url.PathEscape(user), url.PathEscape(pass), host, port))
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("proxy invalide: %s", raw)
	}
	return u, nil
}

func (p *proxyPool) hasProxies() bool {
	return p != nil && len(p.proxies) > 0
}

func (p *proxyPool) first() *url.URL {
	if !p.hasProxies() {
		return nil
	}
	return p.proxies[0]
}

func newDiscoverHTTPClient() *http.Client {
	transport := &http.Transport{}
	pool := getProxyPool()
	if pool.hasProxies() {
		proxy := pool.first()
		transport.Proxy = http.ProxyURL(proxy)
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
