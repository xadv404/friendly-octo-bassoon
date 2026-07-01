package discover

import (
	"net/url"
	"strings"
)

// NormalizeSwissDomain normalise un domaine cible suisse (css → css.ch).
func NormalizeSwissDomain(d string) string {
	d = strings.TrimPrefix(strings.TrimSpace(d), "*.")
	d = strings.TrimPrefix(d, "www.")
	lower := strings.ToLower(d)
	if !strings.Contains(lower, ".") {
		return lower + ".ch"
	}
	return lower
}

// IsSwissHost vérifie qu'un hôte est un domaine .ch (y compris sous-domaines).
func IsSwissHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	return strings.HasSuffix(host, ".ch")
}

// IsSwissURL vérifie qu'une URL pointe vers un domaine .ch.
func IsSwissURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return IsSwissHost(u.Host)
}
