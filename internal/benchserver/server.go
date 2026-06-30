package benchserver

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// Server simule une application web vulnérable pour l'entraînement.
type Server struct {
	URL string
	srv *httptest.Server
}

// New démarre le serveur de test local.
func New() *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/sqli", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") || strings.Contains(id, `"`) {
			fmt.Fprintf(w, "You have an error in your SQL syntax near '%s'", id)
			return
		}
		fmt.Fprintf(w, "User profile for id=%s", id)
	})

	mux.HandleFunc("/xss", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>Results for: %s</body></html>", q)
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if strings.Contains(target, "evil.com") || strings.HasPrefix(target, "//") {
			http.Redirect(w, r, target, 302)
			return
		}
		fmt.Fprint(w, "redirect ok")
	})

	mux.HandleFunc("/file", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Query().Get("path")
		if strings.Contains(path, "passwd") || strings.Contains(path, "../") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
			return
		}
		fmt.Fprintf(w, "content of %s", path)
	})

	mux.HandleFunc("/fetch", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("url")
		if strings.Contains(target, "169.254.169.254") {
			fmt.Fprint(w, `{"ami-id":"ami-12345","instance-id":"i-abc","meta-data":"available"}`)
			return
		}
		if strings.Contains(target, "127.0.0.1") || strings.Contains(target, "localhost") {
			fmt.Fprint(w, "Connection refused connecting to 127.0.0.1")
			return
		}
		fmt.Fprintf(w, "fetched %s", target)
	})

	mux.HandleFunc("/template", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(name, "{{7*7}}") || strings.Contains(name, "${7*7}") {
			fmt.Fprint(w, "Hello 49")
			return
		}
		fmt.Fprintf(w, "Hello %s", name)
	})

	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		users := map[string]string{
			"1": "<div class='profile'>User: Alice, email: alice@corp.com, balance: $12,400</div>",
			"2": "<div class='profile'>User: Bob, email: bob@corp.com, balance: $8,200</div>",
		}
		if u, ok := users[id]; ok {
			fmt.Fprint(w, u)
			return
		}
		http.NotFound(w, r)
	})

	srv := httptest.NewServer(mux)
	return &Server{URL: srv.URL, srv: srv}
}

// Close arrête le serveur.
func (s *Server) Close() {
	s.srv.Close()
}

// Targets retourne les cibles de benchmark avec vulnérabilité attendue.
func (s *Server) Targets() []Target {
	base := s.URL
	return []Target{
		{Name: "SQLi error-based", URL: base + "/sqli?id=1", Param: "id", Expected: "sqli_error"},
		{Name: "XSS reflected", URL: base + "/xss?q=test", Param: "q", Expected: "xss"},
		{Name: "Open Redirect", URL: base + "/redirect?url=/", Param: "url", Expected: "open_redirect"},
		{Name: "LFI / Path Traversal", URL: base + "/file?path=index", Param: "path", Expected: "lfi"},
		{Name: "SSRF", URL: base + "/fetch?url=http://example.com", Param: "url", Expected: "ssrf"},
		{Name: "SSTI", URL: base + "/template?name=world", Param: "name", Expected: "ssti"},
		{Name: "IDOR", URL: base + "/user?id=1", Param: "id", Expected: "idor"},
	}
}

// Target décrit une cible de test.
type Target struct {
	Name     string
	URL      string
	Param    string
	Expected string
}
