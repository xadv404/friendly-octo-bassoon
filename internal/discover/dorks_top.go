package discover

// BuildTopDorks — dorks à fort rendement pour recherche manuelle (1ère page Google).
// Cible : beaucoup d'URLs .ch exploitables (PHP/ASP + paramètres), pas les signatures DBMS niche.
func BuildTopDorks(domain string, subs bool) []string {
	domain = NormalizeSwissDomain(domain)
	if domain == "" {
		return nil
	}
	site := siteOperator(domain, subs)
	c := newDorkCollector(site, 200)

	c.addTemplates(tightScriptTemplates()...)
	c.addTemplates(swissScriptTemplates()...)
	c.addTemplates(compositeTemplates()...)
	c.addTemplates(swissImmoTemplates()...)
	c.addTemplates(swissEmailTemplates()...)

	for _, script := range topPhpScripts() {
		c.addScriptParam(script, "id")
	}
	for _, script := range topAspScripts() {
		c.addScriptParam(script, "id")
	}
	for _, script := range topSwissScripts() {
		c.addScriptParam(script, "id")
	}

	return c.out
}

// topPhpScripts — scripts les plus denses sur .ch (1 param id suffit).
func topPhpScripts() []string {
	return []string{
		"product.php", "category.php", "news.php", "article.php", "gallery.php",
		"profile.php", "detail.php", "view.php", "show.php", "item.php", "page.php",
		"content.php", "display.php", "liste.php", "result.php", "search.php",
		"artikel.php", "shop.php", "catalog.php", "katalog.php", "event.php",
		"agenda.php", "member.php", "download.php", "expose.php", "immo.php",
		"objekt.php", "inserat.php", "promo.php", "news_view.php", "readnews.php",
		"newsitem.php", "product_detail.php", "fiche.php", "annonce.php",
		"veranstaltung.php", "publikation.php", "warenkorb.php", "bestellung.php",
		"newsletter.php", "register.php", "kunde.php", "checkout.php",
	}
}

func topAspScripts() []string {
	return []string{
		"product.asp", "news.asp", "article.asp", "detail.asp", "view.asp",
		"category.asp", "showproduct.asp", "gallery.asp", "search.asp", "shop.asp",
	}
}

func topSwissScripts() []string {
	return []string{
		"Kauf-Suche.php", "Gemeinde-Detail.php", "Objekt-Detail.php",
		"Immobilien-Detail.php", "Makler-Detail.php", "Inserat-Detail.php",
		"Angebot-Detail.php", "Veranstaltung-Detail.php", "News-Detail.php",
		"Artikel-Detail.php", "Produkt-Detail.php",
	}
}
