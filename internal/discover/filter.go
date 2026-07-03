package discover

import (
	"net/url"
	"strings"
)

// hasQueryParams vérifie qu'une URL a au moins un paramètre de requête.
func hasQueryParams(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return len(u.Query()) > 0
}

var noiseURLSuffixes = []string{
	".min.js", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".rar", ".mp4", ".mp3",
}

var noiseURLFragments = []string{
	"/blob/", "/-/blob/", "/-/tree/", "/-/raw/", "/git/", "/assets/", "/static/",
	"/ckeditor/", "/fckeditor/", "/tinymce/", "googleusercontent", "gstatic.com",
	"facebook.com", "twitter.com", "linkedin.com", "youtube.com",
	"/wp-content/", "/wp-includes/", "/wordpress/", "/joomla/", "/typo3/", "/moodle/",
	"/concrete/", "/plugins/", "viewtopic.php", "/mod/url/", "com_jmap", "com_joomla",
	"/wglobal/", "/component/", "jetpack", "woocommerce", "elementor",
}

// isScannable rejette le bruit et garde les URLs avec paramètres.
// requireCHHost=false quand le pays est déjà filtré (OpenSerp country=CH, Bing cc=CH).
func isScannable(raw string, requireCHHost bool) bool {
	if len(raw) > 2048 {
		return false
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return false
	}
	if strings.ContainsAny(raw, "{}") {
		return false
	}
	if strings.Contains(raw, "/$.") || strings.Contains(raw, "/$") {
		return false
	}
	if _, err := url.ParseRequestURI(raw); err != nil {
		return false
	}
	if requireCHHost && !IsSwissURL(raw) {
		return false
	}
	if isNoiseURL(raw) {
		return false
	}
	return hasQueryParams(raw)
}

func isNoiseURL(raw string) bool {
	lower := strings.ToLower(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)
	for _, suf := range noiseURLSuffixes {
		if strings.HasSuffix(path, suf) {
			return true
		}
	}
	for _, frag := range noiseURLFragments {
		if strings.Contains(lower, frag) {
			return true
		}
	}
	return false
}

// normalizeURL nettoie les artefacts Wayback (:80, espaces).
func normalizeURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	return u.String()
}

// matchKeywords retourne true si l'URL contient au moins un mot-clé (path ou URL entière).
func matchKeywords(raw string, keywords []string) bool {
	if len(keywords) == 0 {
		return true
	}
	lower := strings.ToLower(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	path := strings.ToLower(u.Path)

	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw == "" {
			continue
		}
		if strings.Contains(lower, kw) || strings.Contains(path, kw) {
			return true
		}
	}
	return false
}

// matchParamNames retourne true si au moins un nom de param correspond.
func matchParamNames(raw string, paramNames []string) bool {
	if len(paramNames) == 0 {
		return true
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	q := u.Query()
	for _, want := range paramNames {
		want = strings.ToLower(strings.TrimSpace(want))
		if want == "" {
			continue
		}
		for name := range q {
			if strings.EqualFold(name, want) {
				return true
			}
		}
	}
	return false
}
