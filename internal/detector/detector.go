package detector

import (
	"regexp"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

var compiledPatterns map[string][]*regexp.Regexp

func init() {
	compiledPatterns = make(map[string][]*regexp.Regexp)
	for dbms, patterns := range payloads.SQLErrorPatterns {
		compiled := make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			re, err := regexp.Compile("(?i)" + p)
			if err == nil {
				compiled = append(compiled, re)
			}
		}
		compiledPatterns[dbms] = compiled
	}
}

// SQLErrorResult contient le résultat d'une détection d'erreur SQL.
type SQLErrorResult struct {
	Found   bool
	DBMS    string
	Pattern string
	Snippet string
}

// DetectSQLError cherche des erreurs SQL dans le corps de la réponse.
func DetectSQLError(body string) SQLErrorResult {
	// Priorité aux DBMS spécifiques avant generic
	order := []string{"mysql", "postgresql", "mssql", "oracle", "sqlite", "generic"}
	for _, dbms := range order {
		for _, re := range compiledPatterns[dbms] {
			loc := re.FindStringIndex(body)
			if loc != nil {
				snippet := extractSnippet(body, loc[0], loc[1])
				return SQLErrorResult{
					Found:   true,
					DBMS:    dbms,
					Pattern: re.String(),
					Snippet: snippet,
				}
			}
		}
	}
	return SQLErrorResult{}
}

// DetectUnionSuccess détecte une extraction de données DB via UNION.
func DetectUnionSuccess(body, baseline, payload string) bool {
	indicators := []string{
		"@@version", "mysql", "postgresql",
		"microsoft sql server", "sqlite", "ora-",
		"information_schema", "pg_catalog", "sys.databases",
		"mariadb", "5.7.", "8.0.", "14.", "16.",
	}
	bodyLower := strings.ToLower(body)
	baselineLower := strings.ToLower(baseline)
	payloadLower := strings.ToLower(payload)

	// Retirer le payload réfléchi pour éviter les faux positifs
	cleaned := bodyLower
	if payload != "" {
		cleaned = strings.ReplaceAll(cleaned, payloadLower, "")
	}

	for _, ind := range indicators {
		if strings.Contains(cleaned, ind) && !strings.Contains(baselineLower, ind) {
			return true
		}
	}

	for _, fn := range []string{"version()", "database()", "user()"} {
		if strings.Contains(cleaned, fn) && !strings.Contains(baselineLower, fn) {
			return true
		}
	}
	// database() extrait via UNION — mot database seul dans réponse nettoyée
	if strings.Contains(cleaned, "cms_") || strings.Contains(cleaned, "_production") {
		if !strings.Contains(baselineLower, "cms_") {
			return true
		}
	}
	return false
}

// DetectDBLeak détecte des fuites de métadonnées DB dans la réponse.
// Le corps doit différer du baseline (évite faux positifs sur pages statiques).
func DetectDBLeak(body, baseline string) (bool, string) {
	if similarityRatio(baseline, body) < 0.03 {
		return false, ""
	}
	leaks := []struct {
		pattern string
		desc    string
	}{
		{`(?i)\d+\.\d+\.\d+-log\b`, "version MySQL exposée"},
		{`(?i)(postgresql|postgres)\s+\d+\.\d+`, "version PostgreSQL exposée"},
		{`(?i)(root@|postgres@|sa@)`, "utilisateur DB exposé"},
		{`(?i)(information_schema|pg_catalog|sys\.tables)`, "schéma DB exposé"},
		{`(?i)~[^~\s]{4,}~`, "données extraites via EXTRACTVALUE/UPDATEXML"},
	}
	for _, l := range leaks {
		re := regexp.MustCompile(l.pattern)
		if re.FindStringIndex(body) != nil && re.FindStringIndex(baseline) == nil {
			return true, l.desc
		}
	}
	return false, ""
}

// ResponsesDiffer compare deux réponses pour le blind boolean.
func ResponsesDiffer(trueBody, falseBody, baselineBody string, trueCode, falseCode, baselineCode int) (bool, string) {
	if trueCode != falseCode {
		return true, "codes HTTP différents entre payload vrai et faux"
	}

	trueDiff := similarityRatio(baselineBody, trueBody)
	falseDiff := similarityRatio(baselineBody, falseBody)
	trueFalseDiff := similarityRatio(trueBody, falseBody)

	// Le payload vrai doit ressembler au baseline, le faux doit différer
	if trueFalseDiff > 0.15 && falseDiff > trueDiff+0.05 {
		return true, "contenu différent entre payload vrai et faux"
	}

	lenTrue := len(trueBody)
	lenFalse := len(falseBody)
	if lenTrue > 0 && lenFalse > 0 {
		ratio := float64(lenTrue) / float64(lenFalse)
		if ratio > 1.5 || ratio < 0.67 {
			return true, "taille de réponse significativement différente"
		}
	}

	return false, ""
}

func similarityRatio(a, b string) float64 {
	if a == b {
		return 0
	}
	if len(a) == 0 || len(b) == 0 {
		return 1
	}
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}
	diff := 0
	for i := 0; i < minLen; i++ {
		if a[i] != b[i] {
			diff++
		}
	}
	diff += abs(len(a) - len(b))
	return float64(diff) / float64(max(len(a), len(b)))
}

func extractSnippet(body string, start, end int) string {
	pad := 40
	s := start - pad
	if s < 0 {
		s = 0
	}
	e := end + pad
	if e > len(body) {
		e = len(body)
	}
	snippet := strings.TrimSpace(body[s:e])
	if len(snippet) > 200 {
		snippet = snippet[:200] + "..."
	}
	return snippet
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
