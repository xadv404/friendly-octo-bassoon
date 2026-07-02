package benchserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func registerScenarios(mux *http.ServeMux) {
	// ── E-commerce ──
	mux.HandleFunc("/shop/product.php", mysqlErrorHandler("id", "Product"))
	mux.HandleFunc("/shop/search", mysqlUnionHandler("q"))
	mux.HandleFunc("/shop/category", booleanHandler("cat"))

	// ── Auth ──
	mux.HandleFunc("/auth/login", postAware(mysqlErrorHandler("username", "Login attempt")))
	mux.HandleFunc("/api/v1/auth", nosqlAuthHandler("email"))
	mux.HandleFunc("/api/v1/password-reset", postAware(nosqlResetHandler("email")))

	// ── API REST ──
	mux.HandleFunc("/api/v2/users", postgresErrorHandler("user_id"))
	mux.HandleFunc("/api/v2/orders/lookup", jsonNoSQLHandler("orderId"))
	mux.HandleFunc("/api/v1/invoices", mssqlUnionHandler("page"))

	// ── Admin ──
	mux.HandleFunc("/admin/users/search", mssqlErrorHandler("q"))
	mux.HandleFunc("/admin/reports", extractValueHandler("report_id"))
	mux.HandleFunc("/admin/logs", booleanHandler("level"))

	// ── Santé ──
	mux.HandleFunc("/portal/patient", oracleErrorHandler("patient_id"))
	mux.HandleFunc("/portal/lab-results", sqliteErrorHandler("record_id"))

	// ── Banque ──
	mux.HandleFunc("/banking/statement", postgresUnionHandler("account"))
	mux.HandleFunc("/banking/transfer/status", booleanHandler("ref"))

	// ── Blog ──
	mux.HandleFunc("/blog/article", mysqlErrorHandler("slug", "Article"))
	mux.HandleFunc("/blog/comments", mysqlDatabaseUnionHandler("post_id"))

	// ── Legacy ──
	mux.HandleFunc("/artists.php", mysqlErrorHandler("artist", "Artist"))
	mux.HandleFunc("/review.php", postAware(mysqlErrorHandler("product_id", "Review")))

	// ── SaaS ──
	mux.HandleFunc("/crm/contacts", mssqlErrorHandler("contact_id"))
	mux.HandleFunc("/saas/tenants/search", nosqlRegexHandler("name"))

	// ── Voyage ──
	mux.HandleFunc("/booking/hotel", booleanHandler("booking_ref"))
	mux.HandleFunc("/flights/search", postgresErrorHandler("from"))

	// Endpoints extraction
	mux.HandleFunc("/extract/mysql", mysqlExtractHandler("id"))
	mux.HandleFunc("/extract/nosql", nosqlAuthHandler("user"))

	// ── Safe (négatifs) ──
	mux.HandleFunc("/static/about", safeHandler)
	mux.HandleFunc("/safe/users", preparedStatementHandler)
}

// postAware lit GET query ou POST form selon la méthode.
func postAware(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
		}
		fn(w, r)
	}
}

func getParam(r *http.Request, name string) string {
	if r.Method == http.MethodPost {
		return r.FormValue(name)
	}
	return r.URL.Query().Get(name)
}

func mysqlErrorHandler(param, label string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if hasQuote(v) {
			fmt.Fprintf(w, "You have an error in your SQL syntax near '%s' at line 1", v)
			return
		}
		fmt.Fprintf(w, "%s: %s", label, v)
	}
}

func postgresErrorHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if hasQuote(v) {
			fmt.Fprint(w, "ERROR:  syntax error at or near \"'\" LINE 1")
			return
		}
		fmt.Fprintf(w, `{"user_id":"%s","name":"John"}`, v)
	}
}

func mssqlErrorHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if hasQuote(v) {
			fmt.Fprint(w, "Microsoft SQL Native Client error: Unclosed quotation mark after the character string")
			return
		}
		fmt.Fprintf(w, "Results for: %s", v)
	}
}

func oracleErrorHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if hasQuote(v) {
			fmt.Fprint(w, "ORA-01756: quoted string not properly terminated")
			return
		}
		fmt.Fprintf(w, "Patient record: %s", v)
	}
}

func sqliteErrorHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if hasQuote(v) {
			fmt.Fprint(w, "SQLITE_ERROR: near \"'\": syntax error")
			return
		}
		fmt.Fprintf(w, "Lab result: %s", v)
	}
}

func mysqlUnionHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		lower := strings.ToLower(v)
		if strings.Contains(lower, "union") && (strings.Contains(lower, "version") || strings.Contains(lower, "@@")) {
			fmt.Fprint(w, "Search results: 8.0.32-MySQL Community Server")
			return
		}
		fmt.Fprintf(w, "No results for: %s", v)
	}
}

func mssqlUnionHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		lower := strings.ToLower(v)
		if strings.Contains(lower, "union") && strings.Contains(lower, "@@version") {
			fmt.Fprint(w, `{"invoices":[],"db":"Microsoft SQL Server 2019"}`)
			return
		}
		fmt.Fprintf(w, `{"page":%s,"invoices":[]}`, v)
	}
}

func postgresUnionHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		lower := strings.ToLower(v)
		if strings.Contains(lower, "union") && strings.Contains(lower, "version") {
			fmt.Fprint(w, "Statement for account: PostgreSQL 14.10 on x86_64")
			return
		}
		fmt.Fprintf(w, "Account %s: balance $1,234.56", v)
	}
}

func mysqlDatabaseUnionHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		lower := strings.ToLower(v)
		if strings.Contains(lower, "union") && strings.Contains(lower, "database") {
			fmt.Fprint(w, "Comments for post: cms_production")
			return
		}
		fmt.Fprintf(w, "3 comments on post %s", v)
	}
}

func extractValueHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		lower := strings.ToLower(v)
		if strings.Contains(lower, "extractvalue") || strings.Contains(lower, "updatexml") {
			fmt.Fprint(w, "XPATH syntax error: '~8.0.32-MySQL~'")
			return
		}
		fmt.Fprintf(w, "Report %s generated", v)
	}
}

func booleanHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if isBooleanTrue(v) {
			fmt.Fprint(w, strings.Repeat("result ", 50)+"total: 847 items in database")
			return
		}
		if isBooleanFalse(v) {
			fmt.Fprint(w, "total: 0 items")
			return
		}
		fmt.Fprintf(w, "total: 12 items for %s", v)
	}
}

func nosqlAuthHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if isNoSQLBypass(v) {
			fmt.Fprint(w, `{"nachname":"Meier","vorname":"Hans","email":"user@bluewin.ch","telefon":"0791234567","geburtsdatum":"1985-03-12","strasse":"Bahnhofstrasse 1, 8001 Zürich"}`)
			return
		}
		fmt.Fprint(w, `{"error":"invalid credentials"}`)
	}
}

func nosqlResetHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if strings.Contains(v, "$ne") || strings.Contains(v, "$gt") {
			fmt.Fprint(w, `{"message":"reset sent","users":[{"email":"admin@corp.com"},{"email":"user@test.com"}]}`)
			return
		}
		fmt.Fprint(w, `{"message":"email not found"}`)
	}
}

func nosqlRegexHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		if strings.Contains(v, "$regex") || strings.Contains(v, ".*") {
			fmt.Fprint(w, `{"tenants":[{"name":"Acme Corp","plan":"enterprise"},{"name":"Beta Inc","plan":"pro"}]}`)
			return
		}
		fmt.Fprint(w, `{"tenants":[]}`)
	}
}

func jsonNoSQLHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var data map[string]any
		_ = json.Unmarshal(body, &data)

		raw, _ := json.Marshal(data)
		s := string(raw)
		if strings.Contains(s, "$gt") || strings.Contains(s, "$ne") {
			fmt.Fprint(w, `{"orders":[{"id":"ORD-99999","amount":50000,"customer":"admin"}]}`)
			return
		}
		fmt.Fprint(w, `{"orders":[]}`)
	}
}

func safeHandler(w http.ResponseWriter, r *http.Request) {
	// Ne pas réfléchir le paramètre — page 100% statique
	fmt.Fprint(w, "<html><body>About us — static page, no database</body></html>")
}

func preparedStatementHandler(w http.ResponseWriter, r *http.Request) {
	// Requête préparée : réponse fixe quel que soit l'input
	fmt.Fprint(w, `{"id":"1","name":"User","safe":true}`)
}

func hasQuote(s string) bool {
	return strings.Contains(s, "'") || strings.Contains(s, `"`)
}

func isBooleanTrue(s string) bool {
	upper := strings.ToUpper(s)
	return (strings.Contains(upper, "OR") && strings.Contains(s, "1=1")) ||
		strings.Contains(s, `' OR '1'='1`) || strings.Contains(upper, "OR 1=1")
}

func isBooleanFalse(s string) bool {
	upper := strings.ToUpper(s)
	return (strings.Contains(upper, "AND") && strings.Contains(s, "1=2")) ||
		strings.Contains(s, `' AND '1'='2`) || strings.Contains(upper, "AND 1=2")
}

func isNoSQLBypass(s string) bool {
	return strings.Contains(s, "$gt") || strings.Contains(s, "$ne") ||
		strings.Contains(s, "||") || strings.Contains(s, "$regex")
}

func mysqlExtractHandler(param string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := getParam(r, param)
		lower := strings.ToLower(v)

		if strings.Contains(lower, "extractvalue") || strings.Contains(lower, "updatexml") {
			if strings.Contains(lower, "column_name") && strings.Contains(lower, "users") {
				fmt.Fprint(w, "XPATH syntax error: '~nom,prenom,vorname,nachname,email,telefon,telephone,date_naissance,geburtsdatum,adresse,strasse,plz,iban~'")
				return
			}
			if strings.Contains(lower, "information_schema") && strings.Contains(lower, "table_name") {
				fmt.Fprint(w, "XPATH syntax error: '~users,kunden,clients,versicherte~'")
				return
			}
			if strings.Contains(lower, "row_data") || strings.Contains(lower, "'nom='") {
				fmt.Fprint(w, "XPATH syntax error: '~nom=Meier|prenom=Hans|email=hans.meier@bluewin.ch|tel=0791234567|naissance=1985-03-12|adresse=Bahnhofstrasse 1, 8001 Zürich|iban=CH9300762011623852957;;nom=Dupont|prenom=Marie|email=marie.dupont@sunrise.ch|tel=+41791234567|naissance=1990-05-15|adresse=Rue du Rhône 12, 1204 Genève~'")
				return
			}
			if strings.Contains(lower, "@@version") || strings.Contains(lower, "version") {
				fmt.Fprint(w, "XPATH syntax error: '~8.0.32-MySQL~'")
				return
			}
			if strings.Contains(lower, "database()") {
				fmt.Fprint(w, "XPATH syntax error: '~shop_production~'")
				return
			}
			if strings.Contains(lower, "user()") {
				fmt.Fprint(w, "XPATH syntax error: '~root@localhost~'")
				return
			}
		}

		if strings.Contains(lower, "union") && strings.Contains(lower, "@@version") {
			fmt.Fprint(w, "Item: 8.0.32-MySQL")
			return
		}
		if strings.Contains(lower, "union") && strings.Contains(lower, "database()") {
			fmt.Fprint(w, "Item: shop_production")
			return
		}
		if strings.Contains(lower, "union") && strings.Contains(lower, "information_schema") {
			fmt.Fprint(w, "Item: users,orders,products,payments")
			return
		}

		fmt.Fprintf(w, "Product id=%s", v)
	}
}
