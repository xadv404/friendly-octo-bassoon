package benchmark

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/runner"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
)

// TestVerification_SQLCoverage vérifie 100% des scénarios SQLi (hors NoSQL).
func TestVerification_SQLCoverage(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	opts := models.ScanOptions{
		Mode:        models.ScanFast,
		Categories:  []models.VulnCategory{models.CategorySQLi},
		Techniques:  payloads.DefaultSQLiTechniques(models.ScanFast),
		TimeoutSec:  5,
		Threads:     8,
		RateLimitMs: 0,
		EarlyExit:   false,
	}
	sc := scanner.New(client.New(5, nil, nil), opts, nil, nil)

	var sqlTargets, passed, failed int
	for _, tgt := range srv.VulnTargets() {
		if tgt.DBMS == "mongodb" {
			continue
		}
		sqlTargets++
		target := buildScanTarget(srv.URL, tgt)
		result := sc.Scan(context.Background(), target)

		found := false
		for _, f := range result.Findings {
			if string(f.VulnType) == tgt.Expected {
				found = true
				break
			}
		}
		if found {
			passed++
		} else {
			failed++
			types := detectedTypes(result.Findings)
			t.Errorf("[%s] %s: attendu %s, trouvé [%s]", tgt.Context, tgt.Name, tgt.Expected, strings.Join(types, ", "))
		}
	}

	t.Logf("SQLi coverage: %d/%d (100%% requis)", passed, sqlTargets)
	if passed != sqlTargets {
		t.Fatalf("%d échec(s) SQLi sur %d scénarios", failed, sqlTargets)
	}
}

// TestVerification_NoFalsePositivesSafe vérifie zéro finding sur cibles saines.
func TestVerification_NoFalsePositivesSafe(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	opts := models.ScanOptions{
		Mode:        models.ScanFast,
		Categories:  payloads.DefaultCategories(models.ScanFast),
		TimeoutSec:  5,
		Threads:     8,
		RateLimitMs: 0,
		EarlyExit:   false,
	}
	sc := scanner.New(client.New(5, nil, nil), opts, nil, nil)

	for _, tgt := range srv.SafeTargets() {
		target := buildScanTarget(srv.URL, tgt)
		result := sc.Scan(context.Background(), target)
		if len(result.Findings) > 0 {
			t.Fatalf("faux positif [%s] %s: %v", tgt.Context, tgt.Name, detectedTypes(result.Findings))
		}
	}
}

// TestVerification_NoNoSQLOnSQLEndpoints pas de NoSQL sur endpoints SQL purs.
func TestVerification_NoNoSQLOnSQLEndpoints(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	opts := models.ScanOptions{
		Mode:        models.ScanFast,
		Categories:  payloads.DefaultCategories(models.ScanFast),
		TimeoutSec:  5,
		Threads:     8,
		RateLimitMs: 0,
		EarlyExit:   false,
	}
	sc := scanner.New(client.New(5, nil, nil), opts, nil, nil)

	for _, tgt := range srv.VulnTargets() {
		if tgt.DBMS == "mongodb" {
			continue
		}
		target := buildScanTarget(srv.URL, tgt)
		result := sc.Scan(context.Background(), target)
		for _, f := range result.Findings {
			if f.VulnType == models.NoSQL {
				t.Errorf("faux positif NoSQL sur endpoint SQL [%s] %s", tgt.Name, f.Payload)
			}
		}
	}
}

// TestVerification_ExtractionNoGarbage extractions sans mots parasites.
func TestVerification_ExtractionNoGarbage(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	garbage := []string{"have", "results", "total", "items", "syntax", "error", "near", "group_concat"}

	target := models.ScanTarget{
		URL: srv.URL + "/extract/mysql?id=1", Method: "GET",
		Params: map[string]string{"id": "1"},
	}
	finding := models.Finding{
		URL: target.URL, Parameter: "id",
		VulnType: models.SQLiError, DBMS: "mysql", Confidence: models.Confirmed,
	}

	ext := extractor.New(client.New(5, nil, nil), nil, nil, nil)
	data := ext.ExtractFromFinding(context.Background(), target, finding)

	if len(data) == 0 {
		t.Fatal("expected extractions on /extract/mysql")
	}

	for _, d := range data {
		lower := strings.ToLower(d.Value)
		for _, g := range garbage {
			if lower == g {
				t.Errorf("extraction parasite: %s=%q", d.DataType, d.Value)
			}
		}
	}
}

// TestVerification_FullPipeline E2E scan + extract sur tous les scénarios.
func TestVerification_FullPipeline(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	var targets []models.ScanTarget
	for _, tgt := range srv.VulnTargets() {
		targets = append(targets, buildScanTarget(srv.URL, tgt))
	}

	r := &runner.Runner{
		Version: "test",
		Printer: output.New(true, false),
	}

	report, err := r.Run(context.Background(), runner.Config{
		Targets: targets,
		Opts: models.ScanOptions{
			Mode: models.ScanFast, Categories: payloads.DefaultCategories(models.ScanFast),
			TimeoutSec: 5, Threads: 8, ExtractThreads: 2,
			RateLimitMs: 0, EarlyExit: false,
		},
		UrlConcurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	if report.Vulnerable != len(srv.VulnTargets()) {
		t.Fatalf("pipeline: %d/%d vulns", report.Vulnerable, len(srv.VulnTargets()))
	}
	if report.Vulnerable != report.Scanned {
		t.Logf("note: %d findings sur %d cibles (multi-findings ok)", report.Findings, report.Scanned)
	}

	t.Logf("pipeline OK: %d scanned, %d vulnerable, %d findings, %d extractions",
		report.Scanned, report.Vulnerable, report.Findings, report.Extractions)
}

// TestVerification_AllScenariosRequired 24/24 sans relâchement à 90%.
func TestVerification_AllScenariosRequired(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed != result.Total {
		for _, f := range result.Failed {
			t.Error(f)
		}
		t.Fatalf("%d/%d scénarios — 100%% requis", result.Passed, result.Total)
	}
	if len(result.FalsePos) > 0 {
		t.Fatalf("faux positifs: %s", strings.Join(result.FalsePos, "; "))
	}
	t.Log(fmt.Sprintf("vérification OK: %d/%d, 0 faux positif, %d findings", result.Passed, result.Total, result.Findings))
}
