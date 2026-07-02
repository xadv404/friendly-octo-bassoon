package discover

import (
	"fmt"
	"strings"
)

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
	c := newDorkCollector(site, 256)
	c.addTemplates(highYieldTemplates()...)
	c.addTemplates(swissScriptTemplates()...)
	c.addTemplates(compositeTemplates()...)
	c.addTemplates(freshBroadTemplates()...)
	c.addTemplates(swissImmoTemplates()...)
	for _, script := range freshPhpScripts() {
		c.addScript(script)
		c.addScriptParam(script, "id")
		c.addScriptParam(script, "pid")
		c.addScriptParam(script, "cat")
		c.addScriptParam(script, "page")
	}
	for _, param := range swissImmoParams() {
		c.addParam(param)
	}
	return c.out
}

func buildAllDorks(site string) []string {
	c := newDorkCollector(site, 3200)

	c.addTemplates(highYieldTemplates()...)
	c.addTemplates(swissScriptTemplates()...)
	c.addTemplates(compositeTemplates()...)
	c.addTemplates(broadTemplates()...)
	c.addTemplates(pathHintTemplates()...)
	c.addTemplates(swissPathTemplates()...)
	c.addTemplates(swissImmoTemplates()...)
	c.addTemplates(multiParamTemplates()...)

	for _, script := range ghdbPhpScripts() {
		c.addScript(script)
	}
	for _, script := range ghdbAspScripts() {
		c.addScript(script)
	}
	for _, script := range swissPhpScripts() {
		c.addScript(script)
	}

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
	for _, script := range swissPhpScripts() {
		for _, param := range swissImmoParams() {
			c.addScriptParam(script, param)
		}
	}

	for _, param := range sqliParamNames() {
		c.addParam(param)
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

func (c *dorkCollector) add(d string) {
	if isForbiddenDork(d) {
		return
	}
	if _, ok := c.seen[d]; ok {
		return
	}
	c.seen[d] = struct{}{}
	c.out = append(c.out, d)
}

func (c *dorkCollector) addTemplates(templates ...string) {
	for _, p := range templates {
		c.add(fmt.Sprintf(p, c.site))
	}
}

func (c *dorkCollector) addScript(script string) {
	c.add(fmt.Sprintf(`%s inurl:%s inurl:?`, c.site, script))
	c.add(fmt.Sprintf(`%s inurl:%s inurl:&`, c.site, script))
}

func (c *dorkCollector) addScriptParam(script, param string) {
	c.add(fmt.Sprintf(`%s inurl:%s inurl:?%s=`, c.site, script, param))
}

func (c *dorkCollector) addParam(param string) {
	c.add(fmt.Sprintf(`%s inurl:?%s=`, c.site, param))
	c.add(fmt.Sprintf(`%s inurl:&%s=`, c.site, param))
}

func isForbiddenDork(d string) bool {
	lower := strings.ToLower(d)
	forbidden := []string{"joomla", "drupal", "wp-content", "index.php?id=", "sql syntax"}
	for _, bad := range forbidden {
		if strings.Contains(lower, bad) {
			return true
		}
	}
	return false
}

func broadTemplates() []string {
	return []string{
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
		`%s inurl:php?uid=`,
		`%s inurl:php?article=`,
		`%s inurl:php?news=`,
		`%s inurl:php?product=`,
		`%s inurl:php?item=`,
		`%s inurl:php?num=`,
		`%s inurl:asp?id=`,
		`%s inurl:aspx?id=`,
	}
}

func freshBroadTemplates() []string {
	return []string{
		`%s ext:php inurl:?`,
		`%s inurl:php?id=`,
		`%s inurl:php?pid=`,
		`%s inurl:php?cat=`,
		`%s inurl:product.php inurl:?id=`,
		`%s inurl:category.php inurl:?id=`,
		`%s inurl:news.php inurl:?id=`,
		`%s inurl:article.php inurl:?id=`,
		`%s inurl:gallery.php inurl:?id=`,
		`%s inurl:profile.php inurl:?id=`,
		`%s inurl:detail.php inurl:?id=`,
		`%s inurl:view.php inurl:?id=`,
		`%s inurl:show.php inurl:?id=`,
		`%s (inurl:id= | inurl:pid= | inurl:cat=) inurl:&`,
		`%s (inurl:view.php | inurl:detail.php | inurl:product.php) inurl:?id=`,
	}
}

func swissImmoTemplates() []string {
	return []string{
		`%s inurl:RegionRef inurl:.php inurl:?`,
		`%s inurl:Gemeinde- inurl:.php inurl:?`,
		`%s inurl:Kauf-Suche.php inurl:?`,
		`%s inurl:Kauf-Suche inurl:?`,
		`%s inurl:immobilien inurl:Gemeinde inurl:?`,
		`%s inurl:immobilien inurl:RegionRef inurl:?`,
		`%s inurl:liegenschaft inurl:detail inurl:?`,
		`%s inurl:expose inurl:objekt inurl:?`,
		`%s inurl:makler inurl:detail inurl:?`,
		`%s inurl:pageNum_rsVignettes=`,
		`%s inurl:totalRows_rsVignettes=`,
		`%s inurl:?D1= inurl:D2=`,
		`%s inurl:Gemeinde inurl:?D1=`,
		`%s inurl:kanton inurl:detail.php inurl:?`,
		`%s inurl:gemeinde inurl:detail.php inurl:?`,
	}
}

func multiParamTemplates() []string {
	return []string{
		`%s (inurl:id= | inurl:pid= | inurl:cat=) inurl:&`,
		`%s (inurl:page= | inurl:pg= | inurl:p=) inurl:&`,
		`%s (inurl:uid= | inurl:user_id= | inurl:userid=) inurl:&`,
		`%s (inurl:article= | inurl:news= | inurl:nid=) inurl:&`,
		`%s (inurl:product= | inurl:product_id= | inurl:item=) inurl:&`,
		`%s (inurl:view.php | inurl:detail.php | inurl:show.php) inurl:?id=`,
		`%s (inurl:product.php | inurl:category.php | inurl:news.php) inurl:?id=`,
		`%s (inurl:article.php | inurl:gallery.php | inurl:profile.php) inurl:?id=`,
		`%s ext:php (inurl:id= | inurl:cat= | inurl:page=)`,
		`%s ext:asp (inurl:id= | inurl:cat= | inurl:page=)`,
	}
}

func topSqliParams() []string {
	return comboParams()
}

// comboParams — paramètres les plus fréquents pour les paires script×param (limite le volume total).
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
		"forum.php", "topic.php", "photo.php", "album.php", "press.php",
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
