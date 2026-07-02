package benchserver

// Context décrit le type d'application réelle simulée.
type Context string

const (
	ContextEcommerce  Context = "e-commerce"
	ContextAuth       Context = "authentification"
	ContextAPI        Context = "api-rest"
	ContextAdmin      Context = "panel-admin"
	ContextHealthcare Context = "santé"
	ContextBanking    Context = "banque"
	ContextBlog       Context = "blog/cms"
	ContextLegacy     Context = "legacy-php"
	ContextSaaS       Context = "saas-b2b"
	ContextTravel     Context = "réservation"
)

// Target décrit un scénario de test réaliste.
type Target struct {
	Name        string
	Context     Context
	DBMS        string
	Method      string
	URL         string
	Param       string
	Data        map[string]string
	JSONBody    map[string]any
	Expected    string
	Description string
	RealWorld   string // exemple réel inspirant le scénario
}

// Targets retourne tous les scénarios de test.
func (s *Server) Targets() []Target {
	base := s.URL
	return []Target{
		// ── E-commerce ──
		{
			Name: "Produit par ID (MySQL error)", Context: ContextEcommerce, DBMS: "mysql",
			Method: "GET", URL: base + "/shop/product.php", Param: "id",
			Expected:    "sqli_error",
			Description: "Fiche produit avec ID numérique non filtré dans SELECT",
			RealWorld:   "Inspiré de testphp.vulnweb.com/listproducts.php — faille classique e-commerce",
		},
		{
			Name: "Recherche catalogue (MySQL UNION)", Context: ContextEcommerce, DBMS: "mysql",
			Method: "GET", URL: base + "/shop/search", Param: "q",
			Expected:    "sqli_union",
			Description: "Barre de recherche avec UNION injectable exposant la version MySQL",
			RealWorld:   "Bug bounty retail : extraction @@version via UNION sur paramètre search",
		},
		{
			Name: "Filtre catégorie (boolean blind)", Context: ContextEcommerce, DBMS: "mysql",
			Method: "GET", URL: base + "/shop/category", Param: "cat",
			Expected:    "sqli_boolean",
			Description: "Listing catégorie — réponse différente selon OR 1=1 vs AND 1=2",
			RealWorld:   "Blind SQLi sur filtre cat= en boutique en ligne",
		},

		// ── Authentification ──
		{
			Name: "Login POST formulaire (MySQL error)", Context: ContextAuth, DBMS: "mysql",
			Method: "POST", URL: base + "/auth/login", Param: "username",
			Data:        map[string]string{"username": "admin", "password": "test"},
			Expected:    "sqli_error",
			Description: "Formulaire login — username concaténé dans requête SQL",
			RealWorld:   "admin'-- sur champ username — DVWA / login PHP classique",
		},
		{
			Name: "Login API MongoDB (NoSQL bypass)", Context: ContextAuth, DBMS: "mongodb",
			Method: "GET", URL: base + "/api/v1/auth", Param: "email",
			Expected:    "nosql",
			Description: "API auth Node.js — opérateur $gt bypass sur email",
			RealWorld:   `{"$gt":""} sur login MongoDB — OWASP Juice Shop style`,
		},
		{
			Name: "Reset password (NoSQL $ne)", Context: ContextAuth, DBMS: "mongodb",
			Method: "POST", URL: base + "/api/v1/password-reset", Param: "email",
			Data:        map[string]string{"email": "user@test.com"},
			Expected:    "nosql",
			Description: "Reset mot de passe — $ne null retourne tous les comptes",
			RealWorld:   "NoSQLi sur endpoint forgot-password en bug bounty",
		},

		// ── API REST ──
		{
			Name: "API utilisateur (PostgreSQL error)", Context: ContextAPI, DBMS: "postgresql",
			Method: "GET", URL: base + "/api/v2/users", Param: "user_id",
			Expected:    "sqli_error",
			Description: "Endpoint REST GET /users?user_id= — erreur PostgreSQL visible",
			RealWorld:   "ERROR: syntax error at or near — API Spring Boot / Django REST",
		},
		{
			Name: "API commande JSON (NoSQL)", Context: ContextAPI, DBMS: "mongodb",
			Method: "POST", URL: base + "/api/v2/orders/lookup", Param: "orderId",
			JSONBody:    map[string]any{"orderId": "ORD-12345", "customerId": "C001"},
			Expected:    "nosql",
			Description: "Lookup commande via body JSON — injection sur orderId",
			RealWorld:   "API GraphQL/REST avec MongoDB backend non sanitizé",
		},
		{
			Name: "API pagination (MSSQL UNION)", Context: ContextAPI, DBMS: "mssql",
			Method: "GET", URL: base + "/api/v1/invoices", Param: "page",
			Expected:    "sqli_union",
			Description: "Pagination factures — UNION expose Microsoft SQL Server version",
			RealWorld:   "ASP.NET Web API avec @@version extractible",
		},

		// ── Panel admin ──
		{
			Name: "Admin recherche utilisateur (MSSQL error)", Context: ContextAdmin, DBMS: "mssql",
			Method: "GET", URL: base + "/admin/users/search", Param: "q",
			Expected:    "sqli_error",
			Description: "Panel admin — recherche utilisateur avec erreur SQL Server",
			RealWorld:   "Unclosed quotation mark — panel admin ASP.NET legacy",
		},
		{
			Name: "Admin rapport (EXTRACTVALUE leak)", Context: ContextAdmin, DBMS: "mysql",
			Method: "GET", URL: base + "/admin/reports", Param: "report_id",
			Expected:    "sqli_error",
			Description: "Rapport admin — EXTRACTVALUE fuite version via erreur XML",
			RealWorld:   "Error-based extraction MySQL sur dashboards internes",
		},
		{
			Name: "Admin logs (boolean blind)", Context: ContextAdmin, DBMS: "postgresql",
			Method: "GET", URL: base + "/admin/logs", Param: "level",
			Expected:    "sqli_boolean",
			Description: "Filtre logs admin — boolean blind sur niveau de log",
			RealWorld:   "Blind SQLi sur filtres internes admin panel",
		},

		// ── Santé ──
		{
			Name: "Dossier patient (Oracle error)", Context: ContextHealthcare, DBMS: "oracle",
			Method: "GET", URL: base + "/portal/patient", Param: "patient_id",
			Expected:    "sqli_error",
			Description: "Portail patient — ORA-01756 quoted string not properly terminated",
			RealWorld:   "Healthcare apps avec Oracle DB — failles sur patient_id",
		},
		{
			Name: "Résultats labo (SQLite error)", Context: ContextHealthcare, DBMS: "sqlite",
			Method: "GET", URL: base + "/portal/lab-results", Param: "record_id",
			Expected:    "sqli_error",
			Description: "App mobile backend SQLite — erreur near syntax",
			RealWorld:   "SQLite embarqué dans apps santé / IoT médical",
		},

		// ── Banque ──
		{
			Name: "Relevé compte (PostgreSQL UNION)", Context: ContextBanking, DBMS: "postgresql",
			Method: "GET", URL: base + "/banking/statement", Param: "account",
			Expected:    "sqli_union",
			Description: "Relevé bancaire — UNION SELECT version() PostgreSQL",
			RealWorld:   "Fintech bug bounty — extraction version() sur numéro compte",
		},
		{
			Name: "Virement référence (boolean blind)", Context: ContextBanking, DBMS: "mysql",
			Method: "GET", URL: base + "/banking/transfer/status", Param: "ref",
			Expected:    "sqli_boolean",
			Description: "Suivi virement — boolean blind sur référence transaction",
			RealWorld:   "Blind SQLi sur ref= dans apps bancaires",
		},

		// ── Blog / CMS ──
		{
			Name: "Article par slug (MySQL error)", Context: ContextBlog, DBMS: "mysql",
			Method: "GET", URL: base + "/blog/article", Param: "slug",
			Expected:    "sqli_error",
			Description: "CMS WordPress-like — slug injecté dans requête",
			RealWorld:   "Plugins CMS vulnérables sur paramètre slug/post_id",
		},
		{
			Name: "Commentaires (MySQL UNION database)", Context: ContextBlog, DBMS: "mysql",
			Method: "GET", URL: base + "/blog/comments?post_id=1", Param: "post_id",
			Expected:    "sqli_union",
			Description: "Liste commentaires — UNION expose database()",
			RealWorld:   "Extraction database() via UNION sur post_id en CMS",
		},

		// ── Legacy PHP ──
		{
			Name: "Artistes (legacy GET)", Context: ContextLegacy, DBMS: "mysql",
			Method: "GET", URL: base + "/artists.php", Param: "artist",
			Expected:    "sqli_error",
			Description: "Page PHP legacy — paramètre artist non échappé",
			RealWorld:   "testphp.vulnweb.com/artists.php?artist=1",
		},
		{
			Name: "Avis produit (legacy POST)", Context: ContextLegacy, DBMS: "mysql",
			Method: "POST", URL: base + "/review.php", Param: "product_id",
			Data:        map[string]string{"product_id": "42", "rating": "5", "comment": "ok"},
			Expected:    "sqli_error",
			Description: "Formulaire avis POST — product_id injectable",
			RealWorld:   "Sites PHP anciens avec POST non préparé",
		},

		// ── SaaS B2B ──
		{
			Name: "CRM contact lookup (MSSQL)", Context: ContextSaaS, DBMS: "mssql",
			Method: "GET", URL: base + "/crm/contacts", Param: "contact_id",
			Expected:    "sqli_error",
			Description: "CRM SaaS — lookup contact avec erreur SQL Server",
			RealWorld:   "Salesforce-like apps avec SQL Server backend",
		},
		{
			Name: "SaaS tenant search (NoSQL regex)", Context: ContextSaaS, DBMS: "mongodb",
			Method: "GET", URL: base + "/saas/tenants/search?name=acme", Param: "name",
			Expected:    "nosql",
			Description: "Multi-tenant SaaS — $regex dump toutes les organisations",
			RealWorld:   "NoSQL $regex sur recherche tenant en apps B2B",
		},

		// ── Réservation / voyage ──
		{
			Name: "Réservation hôtel (boolean)", Context: ContextTravel, DBMS: "mysql",
			Method: "GET", URL: base + "/booking/hotel", Param: "booking_ref",
			Expected:    "sqli_boolean",
			Description: "Confirmation réservation — blind sur booking_ref",
			RealWorld:   "Apps Booking.com-like avec ref injectable",
		},
		{
			Name: "Vol recherche (PostgreSQL error)", Context: ContextTravel, DBMS: "postgresql",
			Method: "GET", URL: base + "/flights/search", Param: "from",
			Expected:    "sqli_error",
			Description: "Moteur vols — aéroport départ injecté dans PG query",
			RealWorld:   "Travel apps avec PostgreSQL — param from/to classique",
		},

		// ── Négatifs (ne doivent PAS détecter) ──
		{
			Name: "[NEGATIF] Page statique", Context: "safe", DBMS: "none",
			Method: "GET", URL: base + "/static/about", Param: "lang",
			Expected:    "",
			Description: "Page sans DB — aucune injection attendue",
			RealWorld:   "Faux positif check",
		},
		{
			Name: "[NEGATIF] API préparée", Context: "safe", DBMS: "none",
			Method: "GET", URL: base + "/safe/users", Param: "id",
			Expected:    "",
			Description: "Requêtes préparées — injection impossible",
			RealWorld:   "App correctement sécurisée",
		},
	}
}
