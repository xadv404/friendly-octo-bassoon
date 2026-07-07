package alert

import (
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func truncURL(u string, n int) string {
	u = strings.TrimSpace(u)
	if len(u) <= n {
		return u
	}
	return u[:n-1] + "…"
}

func formatFinding(f models.Finding) string {
	lines := []string{
		"URL: " + truncURL(f.URL, 120),
		"param: " + f.Parameter,
		"type: " + string(f.VulnType),
	}
	if f.DBMS != "" {
		lines = append(lines, "dbms: "+f.DBMS)
	}
	return strings.Join(lines, "\n")
}

func formatDumpDetail(d models.ExtractedData, email string) string {
	lines := []string{
		"URL: " + truncURL(d.FindingURL, 120),
		"param: " + d.Parameter,
		"type: " + string(d.VulnType),
	}
	if d.DBMS != "" {
		lines = append(lines, "dbms: "+d.DBMS)
	}
	if email != "" {
		lines = append(lines, "email: "+email)
	}
	if d.PII != nil {
		if d.PII.Prenom != "" || d.PII.Nom != "" {
			lines = append(lines, "nom: "+strings.TrimSpace(d.PII.Prenom+" "+d.PII.Nom))
		}
		if d.PII.Telephone != "" {
			lines = append(lines, "tel: "+d.PII.Telephone)
		}
	}
	return strings.Join(lines, "\n")
}
