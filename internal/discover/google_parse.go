package discover

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	reGoogleURL      = regexp.MustCompile(`(?i)/url\?(?:[^"']*&)?q=([^&"']+)`)
	reGoogleDirectCH = regexp.MustCompile(`(?i)https?://[a-zA-Z0-9._\-]+\.ch[^\s"'<>\\]*`)
	reGoogleSkip     = regexp.MustCompile(`(?i)(google\.|gstatic\.com|youtube\.com|webcache|googleusercontent)`)
	reGoogleJSONURL  = regexp.MustCompile(`"(?:url|link|ou)":"(https?://[^"\\]+)"`)
	reGoogleJSONArray = regexp.MustCompile(`\["(https?://[^"\\]+\.ch[^"\\]*)"(?:,|\])`)
	reGoogleDataHref = regexp.MustCompile(`(?i)data-href="(https?://[^"]+)"`)
)

func parseGoogleResults(html string) []string {
	seen := make(map[string]struct{})
	var out []string

	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		decoded, err := url.QueryUnescape(raw)
		if err == nil && decoded != "" {
			raw = decoded
		}
		raw = strings.ReplaceAll(raw, `\u0026`, "&")
		raw = strings.ReplaceAll(raw, `\u003d`, "=")
		raw = strings.TrimRight(raw, `.,;)`)
		if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
			return
		}
		if reGoogleSkip.MatchString(raw) {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		out = append(out, raw)
	}

	for _, m := range reGoogleURL.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reGoogleJSONURL.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reGoogleJSONArray.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	for _, m := range reGoogleDataHref.FindAllStringSubmatch(html, -1) {
		add(m[1])
	}
	if len(out) == 0 {
		for _, m := range reGoogleDirectCH.FindAllString(html, -1) {
			add(m)
		}
	}
	return out
}
