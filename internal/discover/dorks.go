package discover

import (
	"fmt"
	"strings"
)

// BuildVulnDorks retourne des dorks Google/Bing pour URLs vulnérables (Suisse).
func BuildVulnDorks(domain string, subs bool) []string {
	domain = NormalizeSwissDomain(domain)
	if domain == "" {
		return nil
	}
	return buildAllDorks(siteOperator(domain, subs))
}

// BuildFreshDorks retourne les dorks à fort rendement pour le fresh-pass quotidien
// (page 0 à chaque run — nouveaux sites indexés par Google).
func BuildFreshDorks(domain string, subs bool) []string {
	domain = NormalizeSwissDomain(domain)
	if domain == "" {
		return nil
	}
	return buildFreshDorks(siteOperator(domain, subs))
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
	c := newDorkCollector(site, 80)
	c.addTemplates(swissEmailTemplates()...)
	c.addTemplates(swissImmoTemplates()...)
	for _, script := range freshPhpScripts() {
		c.addScriptParam(script, "id")
	}
	for _, script := range freshEmailScripts() {
		c.addScriptParam(script, "id")
	}
	return c.out
}

// swissEmailTemplates — pages avec bases clients / newsletter / inscription.
func swissEmailTemplates() []string {
	return []string{
		`%s inurl:newsletter inurl:.php inurl:?id=`,
		`%s inurl:register inurl:.php inurl:?id=`,
		`%s inurl:registration inurl:.php inurl:?id=`,
		`%s inurl:kunde inurl:.php inurl:?id=`,
		`%s inurl:mitglied inurl:.php inurl:?id=`,
		`%s inurl:abo inurl:.php inurl:?id=`,
		`%s inurl:anmelden inurl:.php inurl:?id=`,
		`%s inurl:bestellung inurl:.php inurl:?id=`,
		`%s inurl:checkout inurl:.php inurl:?id=`,
		`%s inurl:login inurl:.php inurl:?id=`,
		`%s inurl:contact inurl:.php inurl:?id=`,
		`%s inurl:member inurl:.php inurl:?id=`,
		`%s inurl:warenkorb inurl:.php inurl:?id=`,
		`%s inurl:inscription inurl:.php inurl:?id=`,
		`%s inurl:shop inurl:.php inurl:?id=`,
	}
}

func freshEmailScripts() []string {
	return []string{
		"kunde.php", "register.php", "registration.php", "newsletter.php",
		"login.php", "contact.php", "bestellung.php", "checkout.php",
		"warenkorb.php", "mitglied.php", "abo.php", "anmelden.php",
	}
}

func buildAllDorks(site string) []string {
	c := newDorkCollector(site, 2800)

	c.addTemplates(tightScriptTemplates()...)
	c.addTemplates(swissScriptTemplates()...)
	c.addTemplates(compositeTemplates()...)
	c.addTemplates(swissImmoTemplates()...)
	c.addTemplates(swissEmailTemplates()...)

	for _, script := range comboPhpScripts() {
		for _, param := range comboParams() {
			c.addScriptParam(script, param)
		}
	}
	for _, script := range ghdbAspScripts() {
		for _, param := range comboParams() {
			c.addScriptParam(script, param)
		}
	}
	for _, script := range ghdbPhpScripts() {
		for _, param := range comboParams() {
			c.addScriptParam(script, param)
		}
	}
	for _, script := range swissPhpScripts() {
		for _, param := range swissImmoParams() {
			c.addScriptParam(script, param)
		}
		for _, param := range comboParams() {
			c.addScriptParam(script, param)
		}
	}

	return c.out
}

type dorkCollector struct {
	site string
	seen map[string]struct{}
	out  []string
}

func newDorkCollector(site string, cap int) *dorkCollector {
	return &dorkCollector{
		site: site,
		seen: make(map[string]struct{}, cap),
		out:  make([]string, 0, cap),
	}
}

const dorkNoiseExclude = "-inurl:wp-content -inurl:wp-includes -inurl:wordpress -inurl:joomla -inurl:typo3 -inurl:moodle -inurl:concrete -inurl:plugins -inurl:viewtopic -inurl:wGlobal -inurl:component/ -inurl:mod/url"

func (c *dorkCollector) add(d string) {
	d = strings.TrimSpace(d + " " + dorkNoiseExclude)
	if isForbiddenDork(d) {
		return
	}
	c.store(d)
}

// addLoose — dorks DBMS (intext + script) : règles assouplies, hors patterns dangereux.
func (c *dorkCollector) addLoose(d string) {
	d = strings.TrimSpace(d + " " + dorkNoiseExclude)
	if isHardForbiddenDork(d) {
		return
	}
	c.store(d)
}

func (c *dorkCollector) addLooseTemplates(templates ...string) {
	for _, p := range templates {
		c.addLoose(formatDork(c.site, p))
	}
}

func (c *dorkCollector) store(d string) {
	if _, ok := c.seen[d]; ok {
		return
	}
	c.seen[d] = struct{}{}
	c.out = append(c.out, d)
}

func (c *dorkCollector) addTemplates(templates ...string) {
	for _, p := range templates {
		c.add(formatDork(c.site, p))
	}
}

func (c *dorkCollector) addScriptParam(script, param string) {
	c.add(dorkWithSite(c.site, fmt.Sprintf("inurl:%s inurl:?%s=", script, param)))
}

func dorkWithSite(site, rest string) string {
	if site == "" {
		return rest
	}
	return site + " " + rest
}

func formatDork(site, pattern string) string {
	if site == "" {
		return strings.TrimSpace(strings.Replace(pattern, "%s ", "", 1))
	}
	return fmt.Sprintf(pattern, site)
}

func isForbiddenDork(d string) bool {
	if isHardForbiddenDork(d) {
		return true
	}
	positive := dorkPositivePart(d)
	hasScript := strings.Contains(positive, ".php") || strings.Contains(positive, ".asp") ||
		strings.Contains(positive, ".jsp")
	hasImmo := strings.Contains(positive, "pagenum_rs") || strings.Contains(positive, "totalrows_rs") ||
		strings.Contains(positive, "gemeinde-") || strings.Contains(positive, "regionref")
	if !hasScript && !hasImmo {
		return true
	}
	return false
}

func isHardForbiddenDork(d string) bool {
	positive := dorkPositivePart(d)
	forbidden := []string{
		"index.php?id=", "sql syntax", "inurl:login.php",
		"ext:php inurl:?", "ext:asp inurl:?",
	}
	for _, bad := range forbidden {
		if strings.Contains(positive, bad) {
			return true
		}
	}
	if strings.HasSuffix(strings.TrimSpace(positive), "inurl:?") {
		return true
	}
	return false
}

func dorkPositivePart(d string) string {
	lower := strings.ToLower(d)
	if idx := strings.Index(lower, " -inurl:"); idx > 0 {
		return lower[:idx]
	}
	return lower
}

// tightScriptTemplates — scripts PHP classiques avec param id explicite (GHDB).
func tightScriptTemplates() []string {
	return []string{
		`%s inurl:product.php inurl:?id=`,
		`%s inurl:category.php inurl:?id=`,
		`%s inurl:news.php inurl:?id=`,
		`%s inurl:article.php inurl:?id=`,
		`%s inurl:gallery.php inurl:?id=`,
		`%s inurl:profile.php inurl:?id=`,
		`%s inurl:detail.php inurl:?id=`,
		`%s inurl:view.php inurl:?id=`,
		`%s inurl:show.php inurl:?id=`,
		`%s inurl:item.php inurl:?id=`,
		`%s inurl:page.php inurl:?id=`,
		`%s inurl:content.php inurl:?id=`,
		`%s inurl:display.php inurl:?id=`,
		`%s inurl:search.php inurl:?id=`,
		`%s inurl:artikel.php inurl:?id=`,
		`%s inurl:shop.php inurl:?id=`,
		`%s inurl:catalog.php inurl:?id=`,
		`%s inurl:katalog.php inurl:?id=`,
		`%s inurl:event.php inurl:?id=`,
		`%s inurl:agenda.php inurl:?id=`,
		`%s inurl:member.php inurl:?id=`,
		`%s inurl:download.php inurl:?id=`,
		`%s inurl:news_view.php inurl:?id=`,
		`%s inurl:readnews.php inurl:?id=`,
		`%s inurl:newsitem.php inurl:?num=`,
		`%s inurl:fiche_spectacle.php inurl:?id=`,
		`%s inurl:select_biblio.php inurl:?id=`,
		`%s (inurl:view.php | inurl:detail.php | inurl:product.php) inurl:?id=`,
		`%s (inurl:product.php | inurl:category.php | inurl:news.php) inurl:?id=`,
		`%s (inurl:article.php | inurl:gallery.php | inurl:profile.php) inurl:?id=`,
	}
}

func swissImmoTemplates() []string {
	return []string{
		`%s inurl:RegionRef inurl:.php inurl:?id=`,
		`%s inurl:Gemeinde- inurl:.php inurl:?id=`,
		`%s inurl:Kauf-Suche.php inurl:?id=`,
		`%s inurl:immobilien inurl:Gemeinde inurl:.php inurl:?id=`,
		`%s inurl:immobilien inurl:RegionRef inurl:.php inurl:?id=`,
		`%s inurl:liegenschaft inurl:detail.php inurl:?id=`,
		`%s inurl:expose.php inurl:?objekt_id=`,
		`%s inurl:makler inurl:detail.php inurl:?id=`,
		`%s inurl:.php inurl:pageNum_rsVignettes=`,
		`%s inurl:.php inurl:totalRows_rsVignettes=`,
		`%s inurl:Gemeinde inurl:.php inurl:?D1=`,
		`%s inurl:kanton inurl:detail.php inurl:?id=`,
		`%s inurl:gemeinde inurl:detail.php inurl:?id=`,
	}
}

// comboParams — paramètres les plus fréquents pour les paires script×param.
func comboParams() []string {
	return []string{
		"id", "ID", "page", "pid", "uid", "cat", "category", "product", "product_id",
		"article", "article_id", "news", "item", "view", "show", "detail", "ref",
		"num", "no", "nid", "aid", "type", "action", "search", "q",
	}
}

// comboPhpScripts — sous-ensemble GHDB pour combinaisons script×param (~50 scripts à fort rendement).
func comboPhpScripts() []string {
	return []string{
		"product.php", "category.php", "news.php", "article.php", "gallery.php",
		"profile.php", "detail.php", "view.php", "show.php", "item.php", "page.php",
		"content.php", "display.php", "liste.php", "result.php", "search.php",
		"artikel.php", "shop.php", "catalog.php", "katalog.php", "event.php",
		"agenda.php", "member.php", "download.php", "expose.php", "immo.php",
		"objekt.php", "inserat.php", "promo.php", "news_view.php", "readnews.php",
		"newsitem.php", "product_detail.php", "product-detail.php", "productlist.php",
		"fiche.php", "annonce.php", "veranstaltung.php", "publikation.php",
		"sql.php", "select_biblio.php", "fiche_spectacle.php", "browse.php",
		"list.php", "listing.php", "results.php", "cart.php", "order.php",
		"photo.php", "album.php", "press.php",
	}
}

func swissImmoParams() []string {
	return []string{
		"D1", "D2", "D3", "D4", "Ct", "pageNum_rsVignettes", "totalRows_rsVignettes",
		"objekt_id", "liegenschaft", "kanton", "gemeinde", "makler", "immo", "expose",
	}
}

// freshPhpScripts — scripts à fort rendement pour le fresh-pass quotidien.
func freshPhpScripts() []string {
	return []string{
		"product.php", "category.php", "news.php", "article.php", "gallery.php",
		"profile.php", "detail.php", "view.php", "show.php", "item.php", "page.php",
		"content.php", "display.php", "liste.php", "result.php", "search.php",
		"artikel.php", "shop.php", "catalog.php", "katalog.php", "event.php",
		"agenda.php", "member.php", "download.php", "expose.php", "immo.php",
		"objekt.php", "inserat.php", "promo.php", "news_view.php", "readnews.php",
		"newsitem.php", "product_detail.php", "product-detail.php", "productlist.php",
		"fiche.php", "annonce.php", "veranstaltung.php", "publikation.php",
	}
}

// ghdbPhpScripts — noms de scripts issus du GHDB et guides SQLi publics.
func ghdbPhpScripts() []string {
	return []string{
		"sql.php", "news_view.php", "select_biblio.php", "humor.php", "aboutbook.php",
		"fiche_spectacle.php", "article.php", "show.php", "newsitem.php", "readnews.php",
		"product.php", "category.php", "news.php", "gallery.php", "profile.php",
		"product_detail.php", "product-detail.php", "productlist.php", "product-list.php",
		"category_list.php", "catalogue.php", "catalog.php", "item.php", "items.php",
		"viewitem.php", "view_item.php", "viewproduct.php", "view_product.php",
		"details.php", "dettaglio.php", "scheda.php", "fiche.php", "annonce.php",
		"displayitem.php", "browse.php", "browseproducts.php", "list.php", "listing.php",
		"listings.php", "results.php", "resultats.php", "ergebnis.php", "angebot.php",
		"offers.php", "shop_item.php", "shopitem.php", "cart.php", "panier.php",
		"warenkorb.php", "order.php", "checkout.php", "facture.php", "invoice.php",
		"download.php", "file.php", "getfile.php", "document.php", "doc.php",
		"member.php", "members.php", "user.php", "users.php", "account.php",
		"profil.php", "register.php", "forum.php", "topic.php", "thread.php",
		"post.php", "blog.php", "entry.php", "event.php", "events.php",
		"calendar.php", "agenda.php", "veranstaltung.php", "photo.php", "photos.php",
		"album.php", "albums.php", "image.php", "images.php", "video.php", "videos.php",
		"media.php", "press.php", "presse.php", "publication.php", "search.php",
		"recherche.php", "suche.php", "find.php", "query.php", "content.php",
		"page.php", "pages.php", "section.php", "rubrique.php", "kategorie.php",
		"cat.php", "produkt.php", "produkte.php", "artikel.php", "immobilier.php",
		"immo.php", "objekt.php", "expose.php", "inserat.php", "makler.php",
		"location.php", "reservation.php", "booking.php", "buchung.php",
		"annonce_detail.php", "detail_annonce.php", "product_info.php",
		"review.php", "reviews.php", "comment.php", "comments.php", "feedback.php",
		"print.php", "printer.php", "pdf.php", "export.php", "report.php",
		"view.php", "detail.php", "display.php", "liste.php", "result.php",
		"shop.php", "katalog.php", "offre.php", "inserate.php", "publikation.php",
		"mitteilung.php", "verein.php", "ferienwohnung.php", "garage.php",
		"bestellung.php", "commande.php", "newsletter.php", "anmeldung.php",
		"produktinfo.php", "artikeldetail.php", "warendetail.php", "objektdetail.php",
		"immobiliendetail.php", "objektansicht.php", "angebotsdetail.php",
	}
}

func ghdbAspScripts() []string {
	return []string{
		"showproduct.asp", "product.asp", "news.asp", "article.asp", "detail.asp",
		"view.asp", "category.asp", "items.asp", "gallery.asp", "profile.asp",
		"display.asp", "list.asp", "results.asp", "search.asp", "content.asp",
		"page.asp", "member.asp", "event.asp", "catalog.asp", "shop.asp",
		"produit.asp", "offre.asp", "annonce.asp", "immobilier.asp", "objekt.asp",
	}
}

// swissPhpScripts — scripts et patterns fréquents sur sites .ch (immo, admin, clubs).
func swissPhpScripts() []string {
	return []string{
		"Kauf-Suche.php", "Gemeinde.php", "Gemeinde-Detail.php", "Kanton.php",
		"RegionRef.php", "Objekt-Detail.php", "Immobilien-Detail.php",
		"Liegenschaft.php", "Makler-Detail.php", "Inserat-Detail.php",
		"Angebot-Detail.php", "Verein-Detail.php", "Club-Detail.php",
		"Veranstaltung-Detail.php", "Publikation-Detail.php", "News-Detail.php",
		"Artikel-Detail.php", "Produkt-Detail.php", "Shop-Detail.php",
		"detail_fr.php", "detail_de.php", "detail_it.php", "page_fr.php", "page_de.php",
	}
}

func swissScriptTemplates() []string {
	return []string{
		`%s inurl:promo.php inurl:?id=`,
		`%s inurl:inserat.php inurl:?id=`,
		`%s inurl:inserate.php inurl:?id=`,
		`%s inurl:expose.php inurl:?id=`,
		`%s inurl:immo.php inurl:?id=`,
		`%s inurl:objekt.php inurl:?id=`,
		`%s inurl:veranstaltung.php inurl:?id=`,
		`%s inurl:publikation.php inurl:?id=`,
		`%s inurl:mitteilung.php inurl:?id=`,
		`%s inurl:verein.php inurl:?id=`,
		`%s inurl:werbung.php inurl:?id=`,
		`%s inurl:suche.php inurl:?id=`,
		`%s inurl:anzeige.php inurl:?id=`,
		`%s inurl:ferienwohnung.php inurl:?id=`,
		`%s inurl:location.php inurl:?id=`,
		`%s inurl:garage.php inurl:?id=`,
		`%s inurl:makler.php inurl:?id=`,
		`%s inurl:devis.php inurl:?id=`,
		`%s inurl:facture.php inurl:?id=`,
		`%s inurl:commande.php inurl:?id=`,
		`%s inurl:bestellung.php inurl:?id=`,
		`%s inurl:newsletter.php inurl:?id=`,
		`%s inurl:register.php inurl:?id=`,
		`%s inurl:anmeldung.php inurl:?id=`,
		`%s (inurl:promo.php | inurl:inserat.php | inurl:expose.php) inurl:?id=`,
		`%s (inurl:immo.php | inurl:objekt.php | inurl:makler.php) inurl:?id=`,
	}
}

func compositeTemplates() []string {
	return []string{
		`%s inurl:immobilier inurl:detail.php inurl:?id=`,
		`%s inurl:immo inurl:detail.php inurl:?id=`,
		`%s inurl:recherche.php inurl:?id=`,
		`%s inurl:produit inurl:detail.php inurl:?id=`,
		`%s inurl:artikel inurl:detail.php inurl:?id=`,
		`%s inurl:gemeinde inurl:detail.php inurl:?id=`,
		`%s inurl:kanton inurl:detail.php inurl:?id=`,
		`%s inurl:commune inurl:detail.php inurl:?id=`,
		`%s inurl:verein inurl:detail.php inurl:?id=`,
		`%s inurl:shop inurl:product.php inurl:?id=`,
		`%s inurl:ferienwohnung inurl:detail.php inurl:?id=`,
		`%s inurl:garage inurl:detail.php inurl:?id=`,
		`%s (inurl:expose.php | inurl:objekt.php) inurl:?id=`,
		`%s inurl:agenda inurl:event.php inurl:?id=`,
		`%s inurl:annonce inurl:detail.php inurl:?id=`,
		`%s inurl:katalog inurl:artikel.php inurl:?id=`,
		`%s inurl:warenkorb inurl:shop.php inurl:?id=`,
		`%s inurl:panier inurl:product.php inurl:?id=`,
	}
}

// BuildEmailDorks alias rétrocompat.
func BuildEmailDorks(domain string, subs bool) []string {
	return BuildVulnDorks(domain, subs)
}

func siteOperator(domain string, subs bool) string {
	domain = NormalizeSwissDomain(domain)
	if IsSwissWide(domain) {
		return "" // géo CH via OpenSerp country=CH / Bing cc=CH
	}
	if subs {
		return "site:*." + domain
	}
	return "site:" + domain
}
