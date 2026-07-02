package discover

import "fmt"

// BuildVulnDorks retourne des dorks Bing pour URLs vulnérables SQLi (.ch).
// Mode large (ch) → site:.ch sans cibler un domaine précis.
func BuildVulnDorks(domain string, subs bool) []string {
	site := siteOperator(domain, subs)
	if site == "" {
		return nil
	}

	patterns := []string{
		`%s inurl:?id=`,
		`%s inurl:?page=`,
		`%s inurl:?pid=`,
		`%s inurl:?uid=`,
		`%s inurl:?user=`,
		`%s inurl:?user_id=`,
		`%s inurl:?userid=`,
		`%s inurl:?cat=`,
		`%s inurl:?category=`,
		`%s inurl:?product=`,
		`%s inurl:?article=`,
		`%s inurl:?news=`,
		`%s inurl:?item=`,
		`%s inurl:?view=`,
		`%s inurl:?show=`,
		`%s inurl:?detail=`,
		`%s inurl:?ref=`,
		`%s inurl:?order=`,
		`%s inurl:?cmd=`,
		`%s inurl:?action=`,
		`%s inurl:?module=`,
		`%s inurl:?file=`,
		`%s inurl:?type=`,
		`%s inurl:?sort=`,
		`%s inurl:?filter=`,
		`%s inurl:?search=`,
		`%s inurl:?q=`,
		`%s inurl:?query=`,
		`%s inurl:?login=`,
		`%s inurl:?member=`,
		`%s inurl:?account=`,
		`%s inurl:?register=`,
		`%s inurl:php?id=`,
		`%s inurl:index.php?id=`,
		`%s inurl:product.php?id=`,
		`%s inurl:page.php?id=`,
		`%s inurl:article.php?id=`,
		`%s inurl:news.php?id=`,
		`%s inurl:view.php?id=`,
		`%s inurl:category.php?id=`,
		`%s inurl:detail.php?id=`,
		`%s inurl:show.php?id=`,
		`%s ext:php "?id="`,
		`%s ext:php "?page="`,
		`%s ext:php "?cat="`,
		`%s ext:php "?product="`,
		`%s ext:asp "?id="`,
		`%s ext:aspx "?id="`,
		`%s ext:php inurl:?`,
		`%s inurl:wp-content inurl:?`,
		`%s inurl:joomla inurl:?`,
		`%s inurl:drupal inurl:?`,
		`%s "sql syntax" ext:php`,
		`%s inurl:api inurl:?`,
		`%s inurl:ajax inurl:?`,
	}

	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, fmt.Sprintf(p, site))
	}
	return out
}

// BuildEmailDorks alias rétrocompat (scan email après vuln trouvée).
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
