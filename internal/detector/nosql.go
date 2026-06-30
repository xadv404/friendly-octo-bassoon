package detector

import (
	"regexp"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

var compiledNoSQL []*regexp.Regexp

func init() {
	for _, p := range payloads.NoSQLErrorPatterns {
		re, err := regexp.Compile("(?i)" + p)
		if err == nil {
			compiledNoSQL = append(compiledNoSQL, re)
		}
	}
}

// NoSQLResult contient le résultat d'une détection NoSQL injection.
type NoSQLResult struct {
	Found    bool
	Evidence string
	Snippet  string
}

// DetectNoSQL détecte une injection NoSQL (accès base document).
func DetectNoSQL(body, baseline, payload string) NoSQLResult {
	// Réponse SQL = pas du NoSQL
	if DetectSQLError(body).Found {
		return NoSQLResult{}
	}

	for _, re := range compiledNoSQL {
		loc := re.FindStringIndex(body)
		if loc != nil {
			return NoSQLResult{
				Found:    true,
				Evidence: "erreur moteur NoSQL",
				Snippet:  truncateStr(body, loc[0], 120),
			}
		}
	}

	if !isNoSQLPayload(payload) {
		return NoSQLResult{}
	}

	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baseline)

	// Les heuristiques de contenu exigent une réponse JSON
	if !looksLikeJSON(body) {
		return NoSQLResult{}
	}

	authMarkers := []string{"admin", "password", "email", "token", "secret", "users", "tenants", "enterprise"}

	for _, m := range authMarkers {
		if strings.Contains(bodyLower, m) && !strings.Contains(baselineLower, m) {
			return NoSQLResult{
				Found:    true,
				Evidence: "bypass authentification NoSQL — données DB accessibles",
				Snippet:  m + " trouvé en réponse",
			}
		}
	}

	// Dump collection : JSON plus riche que le baseline JSON
	if looksLikeJSON(baseline) && len(body) > len(baseline)+50 && jsonContentGrew(body, baseline) {
		return NoSQLResult{
			Found:    true,
			Evidence: "dump collection NoSQL — données supplémentaires exposées",
			Snippet:  truncateStr(body, 0, 120),
		}
	}

	return NoSQLResult{}
}

func isNoSQLPayload(payload string) bool {
	ops := []string{"$gt", "$ne", "$regex", "$where", "$or", "||", "[$ne]"}
	for _, op := range ops {
		if strings.Contains(payload, op) {
			return true
		}
	}
	return false
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func jsonContentGrew(body, baseline string) bool {
	// Évite les faux positifs sur pages texte/HTML plus longues
	if !looksLikeJSON(body) || !looksLikeJSON(baseline) {
		return false
	}
	// Tableau/objet non vide ajouté
	if strings.Contains(body, `"users"`) || strings.Contains(body, `"orders"`) ||
		strings.Contains(body, `"tenants"`) || strings.Contains(body, `"token"`) {
		return true
	}
	return len(body) > len(baseline)*2 && len(body) > 80
}

func truncateStr(s string, start, maxLen int) string {
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	out := strings.TrimSpace(s[start:end])
	if end < len(s) {
		out += "..."
	}
	return out
}
