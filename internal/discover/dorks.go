package discover

import "fmt"

// BuildEmailDorks retourne les dorks Bing orientés extraction email / SQLi (.ch).
func BuildEmailDorks(domain string, subs bool) []string {
	site := siteOperator(domain, subs)
	if site == "" {
		return nil
	}

	patterns := []string{
		`%s inurl:?id=`,
		`%s inurl:?page=`,
		`%s inurl:?uid=`,
		`%s inurl:?user=`,
		`%s inurl:?user_id=`,
		`%s inurl:?userid=`,
		`%s inurl:?email=`,
		`%s inurl:?mail=`,
		`%s inurl:?e_mail=`,
		`%s inurl:?login=`,
		`%s inurl:?member=`,
		`%s inurl:?client=`,
		`%s inurl:?kunde=`,
		`%s inurl:?customer=`,
		`%s inurl:?newsletter=`,
		`%s inurl:?subscribe=`,
		`%s inurl:?account=`,
		`%s inurl:?profil=`,
		`%s inurl:?profile=`,
		`%s inurl:?register=`,
		`%s inurl:?inscription=`,
		`%s inurl:?contact=`,
		`%s inurl:?search=`,
		`%s inurl:?cat=`,
		`%s inurl:?category=`,
		`%s inurl:?product=`,
		`%s inurl:?article=`,
		`%s inurl:?view=`,
		`%s inurl:?ref=`,
		`%s inurl:?order=`,
		`%s inurl:?cmd=`,
		`%s inurl:?item=`,
		`%s inurl:?news=`,
		`%s inurl:?detail=`,
		`%s inurl:?show=`,
		`%s inurl:?module=`,
		`%s inurl:?action=`,
		`%s inurl:php?id=`,
		`%s inurl:index.php?id=`,
		`%s inurl:product.php?id=`,
		`%s inurl:page.php?id=`,
		`%s inurl:article.php?id=`,
		`%s inurl:news.php?id=`,
		`%s inurl:member.php?id=`,
		`%s inurl:user.php?id=`,
		`%s inurl:login.php?`,
		`%s inurl:register.php?`,
		`%s inurl:newsletter.php?`,
		`%s ext:php "?id="`,
		`%s ext:php "?page="`,
		`%s ext:php "?user="`,
		`%s ext:asp "?id="`,
		`%s ext:aspx "?id="`,
		`%s "email" ext:php`,
		`%s "mail" ext:php inurl:?`,
		`%s inurl:wp-content inurl:?`,
		`%s inurl:joomla inurl:?`,
	}

	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		out = append(out, fmt.Sprintf(p, site))
	}
	return out
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
