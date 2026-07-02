package discover

import "fmt"

// BuildVulnDorks retourne des dorks Google/Bing pour URLs vulnérables .ch.
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
	// Tier 0 — scripts dynamiques classiques (meilleur rendement SQLi)
	highYield := []string{
		`%s inurl:view.php inurl:?`,
		`%s inurl:show.php inurl:?`,
		`%s inurl:detail.php inurl:?`,
		`%s inurl:product.php inurl:?`,
		`%s inurl:artikel.php inurl:?`,
		`%s inurl:shop.php inurl:?`,
		`%s inurl:catalog.php inurl:?`,
		`%s inurl:news.php inurl:?`,
		`%s inurl:page.php inurl:?`,
		`%s inurl:item.php inurl:?`,
		`%s inurl:display.php inurl:?`,
		`%s inurl:liste.php inurl:?`,
		`%s inurl:result.php inurl:?`,
		`%s inurl:search.php inurl:?`,
		`%s inurl:recherche.php inurl:?`,
		`%s inurl:katalog.php inurl:?`,
		`%s inurl:angebot.php inurl:?`,
		`%s inurl:offre.php inurl:?`,
		`%s inurl:annonce.php inurl:?`,
		`%s inurl:event.php inurl:?`,
		`%s inurl:agenda.php inurl:?`,
		`%s inurl:reservation.php inurl:?`,
		`%s inurl:booking.php inurl:?`,
		`%s inurl:download.php inurl:?`,
		`%s inurl:gallery.php inurl:?`,
		`%s inurl:member.php inurl:?`,
		`%s inurl:profile.php inurl:?`,
		`%s inurl:login.php inurl:?`,
		`%s (inurl:view.php | inurl:detail.php | inurl:product.php) inurl:?`,
		`%s (inurl:artikel.php | inurl:katalog.php | inurl:shop.php) inurl:?`,
	}

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
		`%s inurl:php?id=`,
		`%s inurl:php?cat=`,
		`%s inurl:php?page=`,
		`%s inurl:php?pid=`,
	}

	// Tier 2 — chemins dynamiques fréquents (CH de/fr)
	pathHints := []string{
		`%s inurl:shop inurl:?`,
		`%s inurl:store inurl:?`,
		`%s inurl:detail inurl:?`,
		`%s inurl:news inurl:?`,
		`%s inurl:blog inurl:?`,
		`%s inurl:forum inurl:?`,
		`%s inurl:produit inurl:?`,
		`%s inurl:produkt inurl:?`,
		`%s inurl:article inurl:?`,
		`%s inurl:artikel inurl:?`,
		`%s inurl:catalog inurl:?`,
		`%s inurl:katalog inurl:?`,
		`%s inurl:list inurl:?`,
		`%s inurl:liste inurl:?`,
		`%s inurl:page inurl:?`,
		`%s inurl:seite inurl:?`,
		`%s inurl:membre inurl:?`,
		`%s inurl:mitglied inurl:?`,
		`%s inurl:client inurl:?`,
		`%s inurl:kunde inurl:?`,
		`%s inurl:panier inurl:?`,
		`%s inurl:warenkorb inurl:?`,
		`%s inurl:recherche inurl:?`,
		`%s inurl:suche inurl:?`,
		`%s inurl:immobilier inurl:?`,
		`%s inurl:immo inurl:?`,
		`%s inurl:objekt inurl:?`,
		`%s inurl:angebot inurl:?`,
		`%s inurl:offre inurl:?`,
		`%s inurl:event inurl:?`,
		`%s inurl:agenda inurl:?`,
		`%s inurl:reservation inurl:?`,
		`%s inurl:buchung inurl:?`,
		`%s inurl:download inurl:?`,
		`%s inurl:galerie inurl:?`,
		`%s inurl:gallery inurl:?`,
		`%s inurl:annonce inurl:?`,
		`%s inurl:rubrique inurl:?`,
		`%s inurl:kategorie inurl:?`,
		`%s inurl:category inurl:?`,
	}

	// Tier 3 — paramètres SQLi fréquents
	params := []string{
		"id", "page", "pid", "uid", "user", "user_id", "userid", "cat", "category",
		"product", "product_id", "article", "article_id", "artikel", "news", "item",
		"view", "show", "detail", "ref", "order", "cmd", "action", "module", "file",
		"type", "sort", "filter", "search", "q", "query", "login", "member", "account",
		"register", "post", "nid", "aid", "sid", "tid", "num", "no", "nr", "doc",
		"report", "client", "customer", "kunde", "profil", "profile", "lang", "sprache",
		"year", "month", "day", "ticket", "invoice", "download", "gallery", "album",
		"photo", "video", "p", "pg", "idx", "rec", "row", "key", "offer", "offre",
		"rubrique", "theme", "seite", "kategorie", "objekt", "immo", "event", "termin",
		"liste", "rubrik", "section", "content", "c", "m", "mod", "id_cat", "id_prod",
	}

	out := make([]string, 0, len(highYield)+len(broad)+len(pathHints)+len(params)*2)
	for _, p := range highYield {
		out = append(out, fmt.Sprintf(p, site))
	}
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
