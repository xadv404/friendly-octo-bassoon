package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/benchserver"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
)

func TestRun_MassScan(t *testing.T) {
	srv := benchserver.New()
	defer srv.Close()

	dir := t.TempDir()
	listPath := filepath.Join(dir, "urls.txt")
	var body string
	for i := 0; i < 50; i++ {
		body += fmt.Sprintf("%s/shop/product.php?id=%d\n", srv.URL, i)
	}
	if err := os.WriteFile(listPath, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "results")
	printer := output.New(true, false)
	r := &Runner{Version: "test", Printer: printer}

	report, err := r.Run(context.Background(), Config{
		ListFile:       listPath,
		OutputDir:      outDir,
		UrlCount:       50,
		UrlConcurrency: 8,
		ProgressEvery:  10,
		Opts: models.ScanOptions{
			Mode: models.ScanFast, Categories: payloads.DefaultCategories(models.ScanFast),
			TimeoutSec: 5, Threads: 4, ExtractThreads: 2,
			RateLimitMs: 0, EarlyExit: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 50 {
		t.Fatalf("scanned %d want 50", report.Scanned)
	}
	if report.Vulnerable == 0 {
		t.Fatal("expected vulns")
	}
}
