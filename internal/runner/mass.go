package runner

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
	"github.com/sqli-hunter/sqli-hunter/internal/targets"
	"github.com/sqli-hunter/sqli-hunter/internal/urllist"
)

// runMass scanne un fichier d'URLs en streaming (1k–100k+).
func (r *Runner) runMass(ctx context.Context, cfg Config) (Report, error) {
	start := time.Now()
	report := Report{Version: r.Version}

	total := cfg.UrlCount
	if total <= 0 {
		n, err := urllist.Count(cfg.ListFile)
		if err != nil {
			return report, err
		}
		total = n
	}

	urlConc := max(1, cfg.UrlConcurrency)
	progressEvery := cfg.ProgressEvery
	if progressEvery <= 0 {
		progressEvery = 100
	}

	r.Printer.SetMassMode(true, progressEvery)

	ref := cfg.ListDefaults
	scanClient := client.NewMass(cfg.Opts.TimeoutSec, ref.Headers, ref.Cookies)
	extractClient := client.NewMass(cfg.Opts.TimeoutSec, ref.Headers, ref.Cookies)

	store, err := results.NewSiteStore(cfg.OutputDir, r.Version)
	if err != nil {
		return report, err
	}

	rateLimit := func() {
		if cfg.Opts.RateLimitMs > 0 {
			time.Sleep(time.Duration(cfg.Opts.RateLimitMs) * time.Millisecond)
		}
	}

	ext := extractor.New(extractClient,
		func(d models.ExtractedData) {
			store.AppendExtraction(d.FindingURL, d)
			if cfg.Opts.Verbose {
				r.Printer.Extraction(d)
			}
		},
		func(msg string) { r.Printer.Verbose(msg) },
		rateLimit,
		cfg.Opts.PIIOnly,
	)

	pool := extractor.NewPool(ext, cfg.Opts.ExtractThreads)
	pool.Start(ctx)

	var (
		scanned    atomic.Int64
		vulnerable atomic.Int64
		findings   atomic.Int64
		skipped    atomic.Int64
	)

	urlCh := make(chan string, 2048)
	errCh := make(chan error, 1)
	go func() {
		errCh <- urllist.Stream(cfg.ListFile, urlCh)
	}()

	sem := make(chan struct{}, urlConc)
	var wg sync.WaitGroup

	for raw := range urlCh {
		if ctx.Err() != nil {
			break
		}

		target, err := targets.FromURL(raw, cfg.ListDefaults)
		if err != nil {
			skipped.Add(1)
			continue
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(t models.ScanTarget) {
			defer wg.Done()
			defer func() { <-sem }()

			tStart := time.Now()
			tr := results.TargetResult{URL: t.URL}

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

			if err := store.Add(tr); err != nil {
				r.Printer.Warning("write: " + err.Error())
			}

			n := scanned.Add(1)
			if len(tr.Findings) > 0 {
				vulnerable.Add(1)
				findings.Add(int64(len(tr.Findings)))
			}

			elapsed := time.Since(start)
			rate := float64(n) / elapsed.Seconds()
			r.Printer.MassProgress(int(n), total, int(vulnerable.Load()), int(skipped.Load()), rate, elapsed)
		}(target)
	}

	wg.Wait()
	pool.CloseAndWait()

	if err := <-errCh; err != nil {
		return report, err
	}

	files, err := store.Finalize()
	if err != nil {
		return report, err
	}

	report.Scanned = int(scanned.Load())
	report.Vulnerable = int(vulnerable.Load())
	report.Findings = int(findings.Load())
	report.DurationMs = time.Since(start).Milliseconds()
	report.OutputFiles = files

	r.Printer.MassSummary(report.Scanned, total, report.Vulnerable, report.Findings, int(skipped.Load()), time.Since(start))
	for _, f := range files {
		r.Printer.Success("→ " + f)
	}

	return report, nil
}
