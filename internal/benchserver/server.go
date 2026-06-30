package benchserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Server simule une application avec injections DB vulnérables.
type Server struct {
	URL string
	srv *httptest.Server
}

// New démarre le serveur de test local.
func New() *Server {
	mux := http.NewServeMux()

	// SQLi error-based
	mux.HandleFunc("/sqli/error", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			fmt.Fprintf(w, "You have an error in your SQL syntax near '%s'", id)
			return
		}
		fmt.Fprintf(w, "User id=%s", id)
	})

	// SQLi union — fuite version MySQL
	mux.HandleFunc("/sqli/union", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(strings.ToLower(id), "union") && strings.Contains(strings.ToLower(id), "version") {
			fmt.Fprint(w, "Result: 8.0.32-MySQL Community Server")
			return
		}
		fmt.Fprintf(w, "Product id=%s", id)
	})

	// SQLi boolean blind
	mux.HandleFunc("/sqli/boolean", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "OR") && strings.Contains(id, "1=1") {
			fmt.Fprint(w, "10 results found in database")
			return
		}
		if strings.Contains(id, "AND") && strings.Contains(id, "1=2") {
			fmt.Fprint(w, "0 results found")
			return
		}
		fmt.Fprint(w, "1 result found")
	})

	// NoSQL injection MongoDB
	mux.HandleFunc("/nosql/login", func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if strings.Contains(user, "$gt") || strings.Contains(user, "$ne") || strings.Contains(user, "||") {
			fmt.Fprint(w, `{"users":[{"username":"admin","password":"hash","email":"admin@db.local","role":"admin"}]}`)
			return
		}
		if user == "guest" {
			fmt.Fprint(w, `{"error":"invalid credentials"}`)
			return
		}
		if strings.Contains(user, "$where") {
			fmt.Fprint(w, "MongoError: $where is not allowed in this context")
			return
		}
		fmt.Fprint(w, `{"error":"invalid credentials"}`)
	})

	srv := httptest.NewServer(mux)
	return &Server{URL: srv.URL, srv: srv}
}

// Close arrête le serveur.
func (s *Server) Close() {
	s.srv.Close()
}

// Targets retourne les cibles de benchmark DB.
func (s *Server) Targets() []Target {
	base := s.URL
	return []Target{
		{Name: "SQLi error-based", URL: base + "/sqli/error?id=1", Param: "id", Expected: "sqli_error"},
		{Name: "SQLi union (version DB)", URL: base + "/sqli/union?id=1", Param: "id", Expected: "sqli_union"},
		{Name: "SQLi boolean blind", URL: base + "/sqli/boolean?id=1", Param: "id", Expected: "sqli_boolean"},
		{Name: "NoSQL injection", URL: base + "/nosql/login?user=guest", Param: "user", Expected: "nosql"},
	}
}

// Target décrit une cible de test.
type Target struct {
	Name     string
	URL      string
	Param    string
	Expected string
}
