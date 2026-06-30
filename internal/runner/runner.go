package runner

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
)

// Config configure une exécution.
type Config struct {
	Targets        []models.ScanTarget
	Opts           models.ScanOptions
	OutputPath     string
	UrlConcurrency int
}

// TargetResult résultat pour une cible.
type TargetResult struct {
	URL            string                 `json:"url"`
	Findings       []models.Finding       `json:"findings"`
	Extractions    []models.ExtractedData `json:"extractions,omitempty"`
	TestedParams   int                    `json:"tested_params"`
	TestedPayloads int                    `json:"tested_payloads"`
	DurationMs     int64                  `json:"duration_ms"`
	Error          string                 `json:"error,omitempty"`
}

// Report rapport global.
type Report struct {
	Version     string         `json:"version"`
	Scanned     int            `json:"scanned"`
	Vulnerable  int            `json:"vulnerable"`
	Findings    int            `json:"findings"`
	Extractions int            `json:"extractions"`
	DurationMs  int64          `json:"duration_ms"`
	Results     []TargetResult `json:"results"`
}

// Runner orchestre scan + extraction.
type Runner struct {
	Version string
	Printer *output.Printer
}

// Run exécute le scan sur toutes les cibles.
func (r *Runner) Run(ctx context.Context, cfg Config) (Report, error) {
	start := time.Now()
	report := Report{Version: r.Version}

	if len(cfg.Targets) == 0 {
		return report, nil
	}

	urlConc := max(1, cfg.UrlConcurrency)
	bulk := len(cfg.Targets) > 1

	ref := cfg.Targets[0]
	scanClient := client.New(cfg.Opts.TimeoutSec, ref.Headers, ref.Cookies)
	extractClient := client.New(cfg.Opts.TimeoutSec, ref.Headers, ref.Cookies)

	rateLimit := func() {
		if cfg.Opts.RateLimitMs > 0 {
			time.Sleep(time.Duration(cfg.Opts.RateLimitMs) * time.Millisecond)
		}
	}

	var (
		allExtractions []models.ExtractedData
		extMu          sync.Mutex
	)

	ext := extractor.New(extractClient,
		func(d models.ExtractedData) {
			extMu.Lock()
			allExtractions = append(allExtractions, d)
			extMu.Unlock()
			r.Printer.Extraction(d)
		},
		func(msg string) { r.Printer.Verbose(msg) },
		rateLimit,
	)

	pool := extractor.NewPool(ext, cfg.Opts.ExtractThreads)
	pool.Start(ctx)

	results := make([]TargetResult, len(cfg.Targets))
	sem := make(chan struct{}, urlConc)
	var wg sync.WaitGroup

	for i, target := range cfg.Targets {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, t models.ScanTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			tStart := time.Now()
			tr := TargetResult{URL: t.URL}

			onFinding := func(f models.Finding) {
				r.Printer.Finding(f)
				pool.Submit(t, f)
			}

			sc := scanner.New(scanClient, cfg.Opts, onFinding,
				func(msg string) { r.Printer.Verbose(msg) },
			)

			result := sc.Scan(ctx, t)
			tr.Findings = result.Findings
			tr.TestedParams = result.TestedParams
			tr.TestedPayloads = result.TestedPayloads
			tr.DurationMs = time.Since(tStart).Milliseconds()
			if len(result.Errors) > 0 {
				tr.Error = result.Errors[0]
			}
			results[idx] = tr

			if bulk {
				r.Printer.ScanProgress(idx+1, len(cfg.Targets), t.URL, len(tr.Findings), time.Since(tStart))
			}
		}(i, target)
	}

	wg.Wait()
	pool.CloseAndWait()

	extMu.Lock()
	for i := range results {
		results[i].Extractions = matchExtractions(allExtractions, results[i].URL, results[i].Findings)
	}
	totalExtractions := len(allExtractions)
	extMu.Unlock()

	vulnerable, totalFindings := 0, 0
	for _, tr := range results {
		if len(tr.Findings) > 0 {
			vulnerable++
			totalFindings += len(tr.Findings)
		}
	}

	report.Scanned = len(cfg.Targets)
	report.Vulnerable = vulnerable
	report.Findings = totalFindings
	report.Extractions = totalExtractions
	report.DurationMs = time.Since(start).Milliseconds()
	report.Results = results

	if bulk {
		r.Printer.Summary(report.Scanned, report.Vulnerable, report.Findings, report.Extractions, time.Since(start))
	} else if len(results) == 1 {
		r.Printer.SingleSummary(models.ScanResult{
			Target:         cfg.Targets[0],
			Findings:       results[0].Findings,
			Extractions:    results[0].Extractions,
			TestedParams:   results[0].TestedParams,
			TestedPayloads: results[0].TestedPayloads,
		})
	}

	if cfg.OutputPath != "" {
		if err := writeReport(cfg.OutputPath, report); err != nil {
			return report, err
		}
		r.Printer.Success("résultats → " + cfg.OutputPath)
	}

	return report, nil
}

func matchExtractions(all []models.ExtractedData, targetURL string, findings []models.Finding) []models.ExtractedData {
	if len(findings) == 0 {
		return nil
	}
	params := make(map[string]bool, len(findings))
	for _, f := range findings {
		params[f.Parameter] = true
	}
	var out []models.ExtractedData
	for _, e := range all {
		if !params[e.Parameter] {
			continue
		}
		if e.FindingURL == targetURL || strings.HasPrefix(e.FindingURL, targetURL) || e.FindingURL == "" {
			out = append(out, e)
		}
	}
	return out
}

func writeReport(path string, report Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
