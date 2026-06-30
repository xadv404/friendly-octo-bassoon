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

	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baseline)
	authMarkers := []string{"admin", "password", "email", "token", "secret", "users", "tenants", "enterprise"}

	// Bypass auth / dump collection
	if strings.Contains(payload, "$gt") || strings.Contains(payload, "$ne") || strings.Contains(payload, "||") ||
		strings.Contains(payload, "$regex") {
		for _, m := range authMarkers {
			if strings.Contains(bodyLower, m) && !strings.Contains(baselineLower, m) {
				return NoSQLResult{
					Found:    true,
					Evidence: "bypass authentification NoSQL — données DB accessibles",
					Snippet:  m + " trouvé en réponse",
				}
			}
		}
		// Dump collection : réponse significativement plus riche
		if len(baseline) > 0 && len(body) > len(baseline)+50 {
			return NoSQLResult{
				Found:    true,
				Evidence: "dump collection NoSQL — données supplémentaires exposées",
				Snippet:  truncateStr(body, 0, 120),
			}
		}
		if len(body) > len(baseline)*2 && len(body) > 80 {
			return NoSQLResult{
				Found:    true,
				Evidence: "réponse anormalement large — possible dump collection",
				Snippet:  truncateStr(body, 0, 120),
			}
		}
	}

	return NoSQLResult{}
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
