package urllist

import (
	"net/url"
	"strings"
)

// IsCHHost indique si l'hôte est un domaine .ch.
func IsCHHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	host = strings.TrimSuffix(host, ".")
	return host == "ch" || strings.HasSuffix(host, ".ch")
}

// FilterCH garde uniquement les URLs dont l'hôte est en .ch.
func FilterCH(urls []string) (kept, dropped []string) {
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil || !IsCHHost(u.Hostname()) {
			dropped = append(dropped, raw)
			continue
		}
		kept = append(kept, raw)
	}
	return kept, dropped
}
