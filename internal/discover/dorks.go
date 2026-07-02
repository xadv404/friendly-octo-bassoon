package discover

import "fmt"

// BuildVulnDorks retourne des dorks Bing larges pour URLs vulnérables .ch uniquement.
func BuildVulnDorks(domain string, subs bool) []string {
	site := siteOperator(domain, subs)
	if site == "" {
		return nil
	}
	return buildAllDorks(site)
}

// DailyDorkOrder fait tourner la liste pour varier les requêtes chaque jour.
func DailyDorkOrder(dorks []string, seed int) []string {
	if len(dorks) == 0 {
		return dorks
	}
	if seed < 0 {
		seed = -seed
	}
	offset := seed % len(dorks)
	out := make([]string, len(dorks))
	for i := range dorks {
		out[i] = dorks[(i+offset)%len(dorks)]
	}
	return out
}

func buildAllDorks(site string) []string {
	// Tier 1 — ultra large
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

	// Tier 2 — chemins dynamiques fréquents (large, pas un CMS précis)
	pathHints := []string{
		`%s inurl:shop inurl:?`,
		`%s inurl:store inurl:?`,
		`%s inurl:detail inurl:?`,
		`%s inurl:news inurl:?`,
		`%s inurl:blog inurl:?`,
		`%s inurl:forum inurl:?`,
		`%s inurl:produit inurl:?`,
		`%s inurl:article inurl:?`,
		`%s inurl:catalog inurl:?`,
		`%s inurl:list inurl:?`,
		`%s inurl:page inurl:?`,
		`%s inurl:membre inurl:?`,
		`%s inurl:client inurl:?`,
		`%s inurl:panier inurl:?`,
		`%s inurl:recherche inurl:?`,
	}

	// Tier 3 — paramètres SQLi fréquents
	params := []string{
		"id", "page", "pid", "uid", "user", "user_id", "userid", "cat", "category",
		"product", "article", "news", "item", "view", "show", "detail", "ref",
		"order", "cmd", "action", "module", "file", "type", "sort", "filter",
		"search", "q", "query", "login", "member", "account", "register",
		"post", "nid", "aid", "sid", "tid", "num", "no", "nr", "doc", "report",
		"client", "customer", "profil", "profile", "lang", "year", "month", "day",
		"ticket", "invoice", "download", "gallery", "album", "photo", "video",
		"p", "pg", "idx", "rec", "row", "key", "offer", "offre", "rubrique", "theme",
	}

	out := make([]string, 0, len(broad)+len(pathHints)+len(params)*2)
	for _, p := range broad {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range pathHints {
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
