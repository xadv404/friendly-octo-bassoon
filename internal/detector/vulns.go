package detector

import (
	"net/http"
	"regexp"
	"strings"
)

const xssCanary = "sqlihunter_xss_7x7"

var xssPayloadMarkers = []string{
	"<script>alert(1)</script>",
	"<script>alert(1)",
	"onerror=alert(1)",
	"onload=alert(1)",
	"<svg/onload=alert(1)",
	"<svg/onload=",
	"javascript:alert(1)",
	xssCanary,
}

// XSSResult contient le résultat d'une détection XSS.
type XSSResult struct {
	Found   bool
	Context string
	Snippet string
}

// DetectXSS cherche une réflexion de payload XSS dans la réponse.
func DetectXSS(body, payload string) XSSResult {
	// Payload réfléchi tel quel
	if strings.Contains(body, payload) {
		return XSSResult{
			Found:   true,
			Context: "réflexion directe du payload",
			Snippet: truncate(body, findIndex(body, payload), 120),
		}
	}

	// Marqueurs partiels (encodage partiel)
	bodyLower := strings.ToLower(body)
	for _, marker := range xssPayloadMarkers {
		if strings.Contains(bodyLower, strings.ToLower(marker)) {
			return XSSResult{
				Found:   true,
				Context: "marqueur XSS détecté dans la réponse",
				Snippet: truncate(body, findIndex(bodyLower, strings.ToLower(marker)), 120),
			}
		}
	}

	// Canary mathématique — laissé à DetectSSTI

	return XSSResult{}
}

// DetectSSTI détecte une injection de template côté serveur.
func DetectSSTI(body, payload string) XSSResult {
	if strings.Contains(payload, "7*7") && strings.Contains(body, "49") && !strings.Contains(body, "7*7") {
		return XSSResult{
			Found:   true,
			Context: "évaluation d'expression template (7*7=49)",
			Snippet: truncate(body, strings.Index(body, "49"), 120),
		}
	}

	templateErrors := []string{
		"TemplateSyntaxError", "jinja2", "twig", "freemarker",
		"Velocity", "Thymeleaf", "Handlebars", "mustache",
		"template error", "undefined variable", "Template render error",
	}
	bodyLower := strings.ToLower(body)
	for _, err := range templateErrors {
		if strings.Contains(bodyLower, strings.ToLower(err)) {
			return XSSResult{
				Found:   true,
				Context: "erreur moteur de template",
				Snippet: err,
			}
		}
	}
	return XSSResult{}
}

// IDORResult contient le résultat d'une détection IDOR.
type IDORResult struct {
	Found    bool
	Evidence string
}

// DetectIDOR compare les réponses pour deux valeurs d'un paramètre ID.
func DetectIDOR(body1, body2 string, code1, code2 int, param string) IDORResult {
	if code1 != 200 || code2 != 200 {
		return IDORResult{}
	}
	if body1 == body2 || len(body1) < 20 || len(body2) < 20 {
		return IDORResult{}
	}
	sim := similarityRatio(body1, body2)
	if sim > 0.05 && sim < 0.85 {
		return IDORResult{
			Found:    true,
			Evidence: "réponses différentes pour valeurs distinctes du paramètre " + param,
		}
	}
	return IDORResult{}
}

// RedirectResult contient le résultat d'une détection open redirect.
type RedirectResult struct {
	Found    bool
	Location string
	Evidence string
}

// DetectOpenRedirect vérifie si la réponse redirige vers un domaine externe.
func DetectOpenRedirect(statusCode int, headers http.Header, body, payload string) RedirectResult {
	loc := headers.Get("Location")
	if loc == "" {
		loc = extractMetaRefresh(body)
	}

	if loc == "" {
		return RedirectResult{}
	}

	locLower := strings.ToLower(loc)
	evilMarkers := []string{"evil.com", "//evil", "google.com"}
	for _, m := range evilMarkers {
		if strings.Contains(locLower, m) {
			return RedirectResult{
				Found:    true,
				Location: loc,
				Evidence: "redirection vers domaine externe : " + loc,
			}
		}
	}

	// Payload réfléchi dans Location
	if strings.Contains(loc, payload) || strings.Contains(loc, "evil.com") {
		return RedirectResult{
			Found:    true,
			Location: loc,
			Evidence: "payload réfléchi dans Location : " + loc,
		}
	}

	// 3xx avec Location contenant le payload
	if statusCode >= 300 && statusCode < 400 && strings.Contains(loc, strings.TrimPrefix(payload, "/")) {
		return RedirectResult{
			Found:    true,
			Location: loc,
			Evidence: "redirection 3xx avec payload : " + loc,
		}
	}

	return RedirectResult{}
}

// LFIResult contient le résultat d'une détection LFI.
type LFIResult struct {
	Found   bool
	Evidence string
	Snippet string
}

var lfiPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)root:.*?:0:0:`),
	regexp.MustCompile(`(?i)\[fonts\]`),
	regexp.MustCompile(`(?i)for 16-bit app support`),
	regexp.MustCompile(`(?i)/bin/(bash|sh)`),
	regexp.MustCompile(`(?i)daemon:.*:/usr/sbin`),
	regexp.MustCompile(`(?i)PD9waHA`), // base64 PHP
}

// DetectLFI cherche des signes de lecture de fichier local.
func DetectLFI(body string) LFIResult {
	for _, re := range lfiPatterns {
		loc := re.FindStringIndex(body)
		if loc != nil {
			return LFIResult{
				Found:    true,
				Evidence: "contenu fichier système détecté",
				Snippet:  truncate(body, loc[0], 120),
			}
		}
	}
	return LFIResult{}
}

// SSRFResult contient le résultat d'une détection SSRF.
type SSRFResult struct {
	Found    bool
	Evidence string
	Snippet  string
}

var ssrfPatterns = []struct {
	re      *regexp.Regexp
	evidence string
}{
	{regexp.MustCompile(`(?i)ami-id`), "métadonnées AWS détectées"},
	{regexp.MustCompile(`(?i)instance-id`), "métadonnées cloud détectées"},
	{regexp.MustCompile(`(?i)compute/metadata`), "Google Cloud metadata"},
	{regexp.MustCompile(`(?i)Connection refused`), "connexion interne refusée (SSRF probable)"},
	{regexp.MustCompile(`(?i)Connection timed out`), "timeout connexion interne"},
	{regexp.MustCompile(`(?i)couldn't connect to host`), "échec connexion host interne"},
	{regexp.MustCompile(`(?i)127\.0\.0\.1`), "référence localhost dans la réponse"},
	{regexp.MustCompile(`(?i)<title>.*(Apache|nginx|IIS).*</title>`), "service interne exposé"},
	{regexp.MustCompile(`(?i)redis_version`), "réponse Redis interne"},
}

// DetectSSRF cherche des signes de requête server-side.
func DetectSSRF(body, payload string) SSRFResult {
	for _, p := range ssrfPatterns {
		loc := p.re.FindStringIndex(body)
		if loc != nil {
			return SSRFResult{
				Found:    true,
				Evidence: p.evidence,
				Snippet:  truncate(body, loc[0], 120),
			}
		}
	}

	// Metadata JSON typique AWS
	if strings.Contains(body, "iam/security-credentials") || strings.Contains(body, "meta-data") {
		return SSRFResult{
			Found:    true,
			Evidence: "endpoint metadata cloud accessible",
			Snippet:  truncate(body, strings.Index(body, "meta"), 120),
		}
	}

	return SSRFResult{}
}

func extractMetaRefresh(body string) string {
	re := regexp.MustCompile(`(?i)content\s*=\s*["']?\d+\s*;\s*url=([^"'\s>]+)`)
	m := re.FindStringSubmatch(body)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

func findIndex(s, sub string) int {
	i := strings.Index(s, sub)
	if i < 0 {
		return 0
	}
	return i
}

func truncate(s string, start, maxLen int) string {
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		start = 0
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	snippet := strings.TrimSpace(s[start:end])
	if end < len(s) {
		snippet += "..."
	}
	return snippet
}
