package runner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

func benchTarget(srv *benchserver.Server, i int) models.ScanTarget {
	t := srv.VulnTargets()[i]
	return models.ScanTarget{
		URL:    t.URL + "?" + t.Param + "=1",
		Method: t.Method,
		Params: map[string]string{t.Param: "1"},
		Data:   t.Data,
	}
}

func TestRun_BulkURLs(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	var urlList []models.ScanTarget
	for i := 0; i < 3; i++ {
		urlList = append(urlList, benchTarget(srv, i))
	}

	printer := output.New(true, false)
	r := &Runner{Version: "test", Printer: printer}

	report, err := r.Run(context.Background(), Config{
		Targets: urlList,
		Opts: models.ScanOptions{
			Mode: models.ScanFast, Categories: payloads.DefaultCategories(models.ScanFast),
			TimeoutSec: 5, Threads: 4, ExtractThreads: 2,
			RateLimitMs: 0, EarlyExit: true,
		},
		UrlConcurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 3 {
		t.Fatalf("scanned %d want 3", report.Scanned)
	}
	if report.Vulnerable == 0 {
		t.Fatal("expected at least one vuln")
	}
}

func TestRun_JSONOutput(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "out.json")
	printer := output.New(true, false)
	r := &Runner{Version: "test", Printer: printer}

	_, err := r.Run(context.Background(), Config{
		Targets:    []models.ScanTarget{benchTarget(srv, 0)},
		OutputPath: out,
		Opts: models.ScanOptions{
			Mode: models.ScanFast, Categories: payloads.DefaultCategories(models.ScanFast),
			TimeoutSec: 5, Threads: 4, RateLimitMs: 0, EarlyExit: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 1 {
		t.Fatalf("json scanned %d", report.Scanned)
	}
}
