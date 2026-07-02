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

// BuildFreshDorks retourne les dorks à fort rendement pour le fresh-pass quotidien
// (page 0 à chaque run — nouveaux sites indexés par Google).
func BuildFreshDorks(domain string, subs bool) []string {
	site := siteOperator(domain, subs)
	if site == "" {
		return nil
	}
	return buildFreshDorks(site)
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

func buildFreshDorks(site string) []string {
	highYield := highYieldTemplates()
	swissScripts := swissScriptTemplates()
	composites := compositeTemplates()

	out := make([]string, 0, len(highYield)+len(swissScripts)+len(composites))
	for _, p := range highYield {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range swissScripts {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range composites {
		out = append(out, fmt.Sprintf(p, site))
	}
	return out
}

func buildAllDorks(site string) []string {
	highYield := highYieldTemplates()
	swissScripts := swissScriptTemplates()
	composites := compositeTemplates()

	// Tier 1 — ultra large
	broad := []string{
		`%s inurl:?`,
		`%s inurl:&`,
		`%s ext:php inurl:?`,
		`%s ext:asp inurl:?`,
		`%s ext:aspx inurl:?`,
		`%s ext:jsp inurl:?`,
		`%s ext:cfm inurl:?`,
		`%s ext:phtml inurl:?`,
		`%s (ext:php | ext:asp | ext:aspx) inurl:?`,
		`%s inurl:php?`,
		`%s inurl:asp?`,
		`%s inurl:aspx?`,
		`%s inurl:php?id=`,
		`%s inurl:php?cat=`,
		`%s inurl:php?page=`,
		`%s inurl:php?pid=`,
		`%s inurl:& -inurl:https ext:php`,
	}

	pathHints := pathHintTemplates()
	swissPaths := swissPathTemplates()
	params := sqliParamNames()

	out := make([]string, 0, 400)
	for _, p := range highYield {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range swissScripts {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range composites {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range broad {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range pathHints {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, p := range swissPaths {
		out = append(out, fmt.Sprintf(p, site))
	}
	for _, param := range params {
		out = append(out, fmt.Sprintf(`%s inurl:?%s=`, site, param))
		out = append(out, fmt.Sprintf(`%s inurl:&%s=`, site, param))
	}
	return out
}

func highYieldTemplates() []string {
	return []string{
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
		`%s inurl:content.php inurl:?`,
		`%s inurl:info.php inurl:?`,
		`%s inurl:print.php inurl:?`,
		`%s (inurl:view.php | inurl:detail.php | inurl:product.php) inurl:?`,
		`%s (inurl:artikel.php | inurl:katalog.php | inurl:shop.php) inurl:?`,
		`%s (inurl:recherche.php | inurl:search.php | inurl:suche.php) inurl:?`,
	}
}

func swissScriptTemplates() []string {
	return []string{
		`%s inurl:promo.php inurl:?`,
		`%s inurl:inserat.php inurl:?`,
		`%s inurl:inserate.php inurl:?`,
		`%s inurl:expose.php inurl:?`,
		`%s inurl:immo.php inurl:?`,
		`%s inurl:objekt.php inurl:?`,
		`%s inurl:veranstaltung.php inurl:?`,
		`%s inurl:publikation.php inurl:?`,
		`%s inurl:mitteilung.php inurl:?`,
		`%s inurl:verein.php inurl:?`,
		`%s inurl:werbung.php inurl:?`,
		`%s inurl:suche.php inurl:?`,
		`%s inurl:anzeige.php inurl:?`,
		`%s inurl:ferienwohnung.php inurl:?`,
		`%s inurl:location.php inurl:?`,
		`%s inurl:garage.php inurl:?`,
		`%s inurl:makler.php inurl:?`,
		`%s inurl:devis.php inurl:?`,
		`%s inurl:facture.php inurl:?`,
		`%s inurl:commande.php inurl:?`,
		`%s inurl:bestellung.php inurl:?`,
		`%s inurl:newsletter.php inurl:?`,
		`%s inurl:register.php inurl:?`,
		`%s inurl:anmeldung.php inurl:?`,
		`%s (inurl:promo.php | inurl:inserat.php | inurl:expose.php) inurl:?`,
		`%s (inurl:immo.php | inurl:objekt.php | inurl:makler.php) inurl:?`,
	}
}

func compositeTemplates() []string {
	return []string{
		`%s inurl:immobilier inurl:detail.php inurl:?`,
		`%s inurl:immo inurl:detail.php inurl:?`,
		`%s inurl:recherche.php inurl:?`,
		`%s inurl:produit inurl:detail.php inurl:?`,
		`%s inurl:artikel inurl:detail.php inurl:?`,
		`%s inurl:gemeinde inurl:detail inurl:?`,
		`%s inurl:kanton inurl:detail inurl:?`,
		`%s inurl:commune inurl:detail inurl:?`,
		`%s inurl:verein inurl:detail inurl:?`,
		`%s inurl:shop inurl:product.php inurl:?`,
		`%s inurl:ferienwohnung inurl:detail inurl:?`,
		`%s inurl:garage inurl:detail inurl:?`,
		`%s (inurl:expose.php | inurl:objekt.php) inurl:?`,
		`%s inurl:agenda inurl:event.php inurl:?`,
		`%s inurl:annonce inurl:detail inurl:?`,
		`%s inurl:katalog inurl:artikel.php inurl:?`,
		`%s inurl:warenkorb inurl:shop.php inurl:?`,
		`%s inurl:panier inurl:product.php inurl:?`,
	}
}

func pathHintTemplates() []string {
	return []string{
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
		`%s inurl:publication inurl:?`,
		`%s inurl:publikation inurl:?`,
		`%s inurl:veranstaltung inurl:?`,
		`%s inurl:inserat inurl:?`,
		`%s inurl:anzeige inurl:?`,
	}
}

func swissPathTemplates() []string {
	return []string{
		`%s inurl:kanton inurl:?`,
		`%s inurl:gemeinde inurl:?`,
		`%s inurl:commune inurl:?`,
		`%s inurl:amt inurl:?`,
		`%s inurl:verwaltung inurl:?`,
		`%s inurl:administration inurl:?`,
		`%s inurl:paroisse inurl:?`,
		`%s inurl:verein inurl:?`,
		`%s inurl:verband inurl:?`,
		`%s inurl:association inurl:?`,
		`%s inurl:ferienwohnung inurl:?`,
		`%s inurl:ferien inurl:?`,
		`%s inurl:location inurl:?`,
		`%s inurl:makler inurl:?`,
		`%s inurl:liegenschaft inurl:?`,
		`%s inurl:garage inurl:?`,
		`%s inurl:autos inurl:?`,
		`%s inurl:fahrzeug inurl:?`,
		`%s inurl:devis inurl:?`,
		`%s inurl:offerte inurl:?`,
		`%s inurl:bestellung inurl:?`,
		`%s inurl:commande inurl:?`,
		`%s inurl:newsletter inurl:?`,
		`%s inurl:anmeldung inurl:?`,
		`%s inurl:inscription inurl:?`,
		`%s inurl:mitteilung inurl:?`,
		`%s inurl:actualite inurl:?`,
		`%s inurl:aktualitaet inurl:?`,
		`%s inurl:rubrik inurl:?`,
		`%s inurl:thema inurl:?`,
	}
}

func sqliParamNames() []string {
	return []string{
		"id", "ID", "page", "pid", "uid", "user", "user_id", "userid", "cat", "category",
		"product", "product_id", "article", "article_id", "artikel", "news", "item",
		"view", "show", "detail", "ref", "order", "cmd", "action", "module", "file",
		"type", "sort", "filter", "search", "q", "query", "login", "member", "account",
		"register", "post", "nid", "aid", "sid", "tid", "num", "no", "nr", "doc",
		"report", "client", "customer", "kunde", "profil", "profile", "lang", "sprache",
		"year", "month", "day", "ticket", "invoice", "download", "gallery", "album",
		"photo", "video", "p", "pg", "idx", "rec", "row", "key", "offer", "offre",
		"rubrique", "theme", "seite", "kategorie", "objekt", "immo", "event", "termin",
		"liste", "rubrik", "section", "content", "c", "m", "mod", "id_cat", "id_prod",
		"mandant", "dossier", "geschaeft", "affaire", "referenz", "referenznummer",
		"nummer", "lieferant", "fournisseur", "agence", "makler", "liegenschaft",
		"kanton", "gemeinde", "paroisse", "werbung", "inserat", "veranstaltung",
		"bestellung", "commande", "anmeldung", "newsletter", "expose", "objekt_id",
	}
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
