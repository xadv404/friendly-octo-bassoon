package benchmark

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
)

// TestE2E_ScanExtract_Timing mesure scan + extraction auto (pool) sur les 24 scénarios.
func TestE2E_ScanExtract_Timing(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	const rateLimitMs = 100

	scanOpts := models.ScanOptions{
		Mode:           models.ScanFast,
		Categories:     payloads.DefaultCategories(models.ScanFast),
		TimeoutSec:     5,
		Threads:        8,
		ExtractThreads: 2,
		RateLimitMs:    rateLimitMs,
		EarlyExit:      true,
	}

	scanClient := client.New(scanOpts.TimeoutSec, nil, nil)
	extractClient := client.New(scanOpts.TimeoutSec, nil, nil)

	rateLimit := func() {
		time.Sleep(time.Duration(rateLimitMs) * time.Millisecond)
	}

	var (
		extractions []models.ExtractedData
		extMu       sync.Mutex
		findCount   int
	)

	ext := extractor.New(extractClient,
		func(d models.ExtractedData) {
			extMu.Lock()
			extractions = append(extractions, d)
			extMu.Unlock()
		},
		nil,
		rateLimit,
	)

	pool := extractor.NewPool(ext, scanOpts.ExtractThreads)
	ctx := context.Background()
	pool.Start(ctx)

	var scanDurations []time.Duration
	totalStart := time.Now()

	for _, tgt := range srv.VulnTargets() {
		target := buildScanTarget(srv.URL, tgt)
		t0 := time.Now()

		onFinding := func(f models.Finding) {
			findCount++
			pool.Submit(target, f)
		}
		sc := scanner.New(scanClient, scanOpts, onFinding, nil)
		sc.Scan(ctx, target)

		scanDurations = append(scanDurations, time.Since(t0))
	}

	pool.CloseAndWait()
	totalElapsed := time.Since(totalStart)

	extMu.Lock()
	extCount := len(extractions)
	extMu.Unlock()

	avgScan := avgDuration(scanDurations)
	p50, p95 := percentile(scanDurations, 50), percentile(scanDurations, 95)

	t.Logf("═══ E2E Scan + Extract (rate-limit %dms) ═══", rateLimitMs)
	t.Logf("  Scénarios vulnérables : %d", len(srv.VulnTargets()))
	t.Logf("  Findings détectés     : %d", findCount)
	t.Logf("  Données extraites     : %d", extCount)
	t.Logf("  Durée scan (somme)    : %s (avg %s, p50 %s, p95 %s)",
		sumDuration(scanDurations).Round(time.Millisecond),
		avgScan.Round(time.Millisecond),
		p50.Round(time.Millisecond),
		p95.Round(time.Millisecond),
	)
	t.Logf("  Durée totale E2E      : %s (scan + extract parallèle, workers=%d)",
		totalElapsed.Round(time.Millisecond), scanOpts.ExtractThreads)

	if findCount == 0 {
		t.Fatal("aucun finding — pipeline cassé")
	}
	if extCount == 0 {
		t.Fatal("aucune extraction — pool cassé")
	}
}

// TestTiming_LargeDB_Projection estime le temps sur des bases volumineuses.
func TestTiming_LargeDB_Projection(t *testing.T) {
	rateLimitMs := 100
	extractWorkers := 2

	dbSizes := []struct {
		name       string
		tables     int
		rowsPerTbl int
		totalRows  int
	}{
		{"Petite (WordPress)", 50, 10_000, 500_000},
		{"Moyenne (SaaS)", 500, 100_000, 50_000_000},
		{"Grosse (e-commerce)", 2_000, 1_000_000, 2_000_000_000},
		{"Très grosse (data warehouse)", 10_000, 10_000_000, 100_000_000_000},
	}

	mysqlJobs := len(extractor.BuildJobs("mysql", models.SQLiUnion))
	metadataReqsBest := 4
	metadataReqsWorst := mysqlJobs

	t.Log("═══ Projection timing — extraction actuelle (métadonnées uniquement) ═══")
	t.Logf("  Requêtes HTTP max par vuln (MySQL) : %d payloads", mysqlJobs)
	t.Logf("  Types extraits : version, database, user, tables (pas de dump lignes)")
	t.Logf("  Rate limit : %dms | Workers extract : %d", rateLimitMs, extractWorkers)
	t.Log("")

	for _, db := range dbSizes {
		metaBest := time.Duration(metadataReqsBest*rateLimitMs) * time.Millisecond
		metaWorst := time.Duration(metadataReqsWorst*rateLimitMs) * time.Millisecond

		tablesVisible := min(db.tables, 32)
		if tablesVisible < db.tables {
			t.Logf("  [%s] ⚠ tables: %d total, ~%d visibles par requête (limite EXTRACTVALUE/GROUP_CONCAT)",
				db.name, db.tables, tablesVisible)
		}

		charsPerRow := 64
		blindReqsPerRow := charsPerRow * 8
		totalBlindReqs := float64(db.totalRows) * float64(blindReqsPerRow)
		blindHours := totalBlindReqs * float64(rateLimitMs) / 1000 / 3600
		blindParallelHours := blindHours / float64(extractWorkers)

		t.Logf("  [%s] %d tables, %s lignes", db.name, db.tables, formatRows(db.totalRows))
		t.Logf("    Métadonnées (outil actuel) : %s – %s par vuln",
			metaBest.Round(time.Millisecond), metaWorst.Round(time.Millisecond))
		t.Logf("    Dump complet blind (non implémenté, estimation) : %s séquentiel, %s avec %d workers",
			formatHours(blindHours), formatHours(blindParallelHours), extractWorkers)
		t.Log("")
	}

	t.Log("═══ Scan 24 scénarios (mesuré localement) ═══")
	srv := benchserver.New()
	defer srv.Close()

	opts := models.ScanOptions{
		Mode: models.ScanFast, Categories: payloads.DefaultCategories(models.ScanFast),
		TimeoutSec: 5, Threads: 8, RateLimitMs: rateLimitMs, EarlyExit: true,
	}
	sc := scanner.New(client.New(5, nil, nil), opts, nil, nil)

	start := time.Now()
	for _, tgt := range srv.VulnTargets() {
		sc.Scan(context.Background(), buildScanTarget(srv.URL, tgt))
	}
	scan24 := time.Since(start)

	t.Logf("  24 cibles, rate-limit %dms : %s (~%s/cible)",
		rateLimitMs, scan24.Round(time.Millisecond), (scan24 / 24).Round(time.Millisecond))

	singleURL := scan24 / 24
	t.Logf("  1 URL bug bounty typique : ~%s scan + ~%s–%s extract = ~%s–%s total",
		singleURL.Round(time.Millisecond),
		time.Duration(metadataReqsBest*rateLimitMs)*time.Millisecond,
		time.Duration(metadataReqsWorst*rateLimitMs)*time.Millisecond,
		(singleURL + time.Duration(metadataReqsBest*rateLimitMs)*time.Millisecond).Round(time.Millisecond),
		(singleURL + time.Duration(metadataReqsWorst*rateLimitMs)*time.Millisecond).Round(time.Millisecond),
	)
}

func avgDuration(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	return sumDuration(d) / time.Duration(len(d))
}

func sumDuration(d []time.Duration) time.Duration {
	var sum time.Duration
	for _, v := range d {
		sum += v
	}
	return sum
}

func percentile(d []time.Duration, p int) time.Duration {
	if len(d) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(d))
	copy(cp, d)
	for i := 0; i < len(cp); i++ {
		for j := i + 1; j < len(cp); j++ {
			if cp[j] < cp[i] {
				cp[i], cp[j] = cp[j], cp[i]
			}
		}
	}
	idx := (p * len(cp)) / 100
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func formatRows(n int) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func formatHours(h float64) string {
	switch {
	case h >= 24*365:
		return fmt.Sprintf("%.1f ans", h/24/365)
	case h >= 24:
		return fmt.Sprintf("%.1f jours", h/24)
	case h >= 1:
		return fmt.Sprintf("%.1f heures", h)
	case h*60 >= 1:
		return fmt.Sprintf("%.1f min", h*60)
	default:
		return fmt.Sprintf("%.1f s", h*3600)
	}
}

func formatDuration(d time.Duration) string {
	switch {
	case d >= 365*24*time.Hour:
		return fmt.Sprintf("%.1f ans", d.Hours()/24/365)
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.1f jours", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.1f heures", d.Hours())
	case d >= time.Minute:
		return fmt.Sprintf("%.1f min", d.Minutes())
	case d >= time.Second:
		return fmt.Sprintf("%.1f s", d.Seconds())
	default:
		return d.Round(time.Millisecond).String()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
