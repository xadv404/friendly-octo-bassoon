package results

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

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

// SiteReport rapport JSON par domaine.
type SiteReport struct {
	Domain      string       `json:"domain"`
	ToolVersion string       `json:"tool_version"`
	GeneratedAt string       `json:"generated_at"`
	Summary     SiteSummary  `json:"summary"`
	Targets     []TargetResult `json:"targets"`
}

// SiteSummary statistiques du domaine.
type SiteSummary struct {
	URLsScanned    int `json:"urls_scanned"`
	URLsVulnerable int `json:"urls_vulnerable"`
	Findings       int `json:"findings"`
	Extractions    int `json:"extractions"`
}

// WriteSites écrit results/DOMAIN/DOMAIN.json et DOMAIN.sql pour chaque site.
func WriteSites(baseDir, toolVersion string, targets []TargetResult) ([]string, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	grouped := groupByDomain(targets)
	var written []string

	for domain, siteTargets := range grouped {
		dir := filepath.Join(baseDir, domain)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return written, fmt.Errorf("mkdir %s: %w", dir, err)
		}

		report := buildSiteReport(domain, toolVersion, siteTargets)
		jsonPath := filepath.Join(dir, domain+".json")
		if err := writeJSON(jsonPath, report); err != nil {
			return written, err
		}
		written = append(written, jsonPath)

		sqlPath := filepath.Join(dir, domain+".sql")
		if err := os.WriteFile(sqlPath, []byte(formatSQL(report)), 0644); err != nil {
			return written, fmt.Errorf("write %s: %w", sqlPath, err)
		}
		written = append(written, sqlPath)
	}
	return written, nil
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

func groupByDomain(targets []TargetResult) map[string][]TargetResult {
	out := make(map[string][]TargetResult)
	for _, t := range targets {
		domain, err := DomainFromURL(t.URL)
		if err != nil {
			domain = "unknown"
		}
		out[domain] = append(out[domain], t)
	}
	return out
}

func buildSiteReport(domain, version string, targets []TargetResult) SiteReport {
	summary := SiteSummary{URLsScanned: len(targets)}
	for _, t := range targets {
		if len(t.Findings) > 0 {
			summary.URLsVulnerable++
			summary.Findings += len(t.Findings)
		}
		summary.Extractions += len(t.Extractions)
	}
	return SiteReport{
		Domain:      domain,
		ToolVersion: version,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:     summary,
		Targets:     targets,
	}
}

func writeJSON(path string, report SiteReport) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func formatSQL(report SiteReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-- sqli-hunter extraction report\n")
	fmt.Fprintf(&b, "-- Domain: %s\n", report.Domain)
	fmt.Fprintf(&b, "-- Generated: %s\n", report.GeneratedAt)
	fmt.Fprintf(&b, "-- URLs: %d scanned, %d vulnerable\n\n",
		report.Summary.URLsScanned, report.Summary.URLsVulnerable)

	for _, t := range report.Targets {
		if len(t.Findings) == 0 && len(t.Extractions) == 0 {
			continue
		}
		b.WriteString("/* " + strings.Repeat("=", 60) + " */\n")
		fmt.Fprintf(&b, "/* URL: %s */\n", t.URL)
		for _, f := range t.Findings {
			fmt.Fprintf(&b, "/* VULN: %s | param: %s | confidence: %s */\n",
				f.VulnType, f.Parameter, f.Confidence)
			if f.Payload != "" {
				fmt.Fprintf(&b, "/* Payload: %s */\n", truncate(f.Payload, 120))
			}
		}
		b.WriteString("/* " + strings.Repeat("=", 60) + " */\n")

		seen := make(map[string]bool)
		for _, e := range t.Extractions {
			key := string(e.DataType) + ":" + e.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			fmt.Fprintf(&b, "-- %s: %s\n", e.DataType, escapeSQLComment(e.Value))
		}
		b.WriteByte('\n')
	}
	return b.String()
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

func escapeSQLComment(s string) string {
	return strings.ReplaceAll(s, "*/", "* /")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
