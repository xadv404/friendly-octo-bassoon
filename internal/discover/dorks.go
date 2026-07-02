package discover

import "fmt"

// BuildVulnDorks retourne des dorks Bing larges pour URLs vulnérables .ch uniquement.
// La localisation suisse est dans chaque requête via site:.ch (pas de ciblage domaine/CMS).
func BuildVulnDorks(domain string, subs bool) []string {
	site := siteOperator(domain, subs)
	if site == "" {
		return nil
	}

	// Tier 1 — ultra large : max d'URLs avec paramètres dynamiques
	broad := []string{
		`%s inurl:?`,
		`%s inurl:&`,
		`%s ext:php inurl:?`,
		`%s ext:asp inurl:?`,
		`%s ext:aspx inurl:?`,
		`%s ext:jsp inurl:?`,
		`%s ext:cfm inurl:?`,
		`%s (ext:php | ext:asp | ext:aspx) inurl:?`,
		`%s inurl:php?`,
		`%s inurl:asp?`,
		`%s inurl:aspx?`,
	}

	// Tier 2 — noms de paramètres SQLi fréquents (sans imposer un chemin/fichier)
	params := []string{
		"id", "page", "pid", "uid", "user", "user_id", "userid", "cat", "category",
		"product", "article", "news", "item", "view", "show", "detail", "ref",
		"order", "cmd", "action", "module", "file", "type", "sort", "filter",
		"search", "q", "query", "login", "member", "account", "register",
		"post", "nid", "aid", "sid", "tid", "num", "no", "nr", "doc", "report",
		"client", "customer", "profil", "profile", "lang", "year", "month", "day",
		"ticket", "invoice", "download", "gallery", "album", "photo", "video",
	}

	out := make([]string, 0, len(broad)+len(params)*2)
	for _, p := range broad {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, param := range params {
		out = append(out, fmt.Sprintf(`%s inurl:?%s=`, site, param))
		out = append(out, fmt.Sprintf(`%s inurl:&%s=`, site, param))
	}
	return out
}

// BuildEmailDorks alias rétrocompat.
func BuildEmailDorks(domain string, subs bool) []string {
	return BuildVulnDorks(domain, subs)
}

func siteOperator(domain string, subs bool) string {
	domain = NormalizeSwissDomain(domain)
	if IsSwissWide(domain) {
		return "site:.ch"
	}
	if subs {
		return "site:*." + domain
	}
	return "site:" + domain
}
