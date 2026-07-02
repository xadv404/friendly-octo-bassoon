package results

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// TargetResult résultat d'une URL scannée (copie légère pour export).
type TargetResult struct {
	URL            string                 `json:"url"`
	Findings       []models.Finding       `json:"findings"`
	Extractions    []models.ExtractedData `json:"extractions,omitempty"`
	TestedParams   int                    `json:"tested_params"`
	TestedPayloads int                    `json:"tested_payloads"`
	DurationMs     int64                  `json:"duration_ms"`
	Error          string                 `json:"error,omitempty"`
}

// WriteSites écrit les emails extraits dans results/emails/<fournisseur>.txt.
func WriteSites(baseDir, toolVersion string, targets []TargetResult) ([]string, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", baseDir, err)
	}
	return WriteEmailsFromTargets(baseDir, targets)
}

// DomainFromURL extrait le hostname d'une URL.
func DomainFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("hostname vide: %s", raw)
	}
	return sanitizeDomain(strings.ToLower(host)), nil
}

func sanitizeDomain(domain string) string {
	domain = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, domain)
	return domain
}
