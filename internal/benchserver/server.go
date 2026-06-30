package benchserver

import (
	"net/http"
	"net/http/httptest"
)

// Server simule des applications réelles vulnérables aux injections DB.
type Server struct {
	URL string
	srv *httptest.Server
}

// New démarre le serveur de test avec tous les scénarios.
func New() *Server {
	mux := http.NewServeMux()
	registerScenarios(mux)
	srv := httptest.NewServer(mux)
	return &Server{URL: srv.URL, srv: srv}
}

// Close arrête le serveur.
func (s *Server) Close() {
	s.srv.Close()
}

// VulnTargets retourne uniquement les scénarios vulnérables (sans négatifs).
func (s *Server) VulnTargets() []Target {
	var out []Target
	for _, t := range s.Targets() {
		if t.Expected != "" {
			out = append(out, t)
		}
	}
	return out
}

// SafeTargets retourne les scénarios sans vulnérabilité attendue.
func (s *Server) SafeTargets() []Target {
	var out []Target
	for _, t := range s.Targets() {
		if t.Expected == "" {
			out = append(out, t)
		}
	}
	return out
}

// TargetsByContext groupe les cibles par contexte applicatif.
func (s *Server) TargetsByContext() map[Context][]Target {
	grouped := make(map[Context][]Target)
	for _, t := range s.VulnTargets() {
		grouped[t.Context] = append(grouped[t.Context], t)
	}
	return grouped
}
