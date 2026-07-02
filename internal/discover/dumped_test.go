package discover

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

func TestRun_SkipsDumpedDomains(t *testing.T) {
	dir := t.TempDir()
	resultsDir := filepath.Join(dir, "results")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(resultsDir, "dumped_domains.txt"), []byte("css.ch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(dir, "scope.txt")
	fetcher := &mockFetcher{pages: [][]string{{
		"https://css.ch/page.php?id=1",
		"https://shop.ch/item.php?id=2",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:     "ch",
		Output:     out,
		Source:     SourceBing,
		ResultsDir: resultsDir,
		SkipDumped: true,
		Fetcher:    fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 1 {
		t.Fatalf("kept %d want 1 (css.ch skipped)", result.Kept)
	}
	if result.Skipped != 1 {
		t.Fatalf("skipped %d want 1", result.Skipped)
	}

	// verify registry loaded
	reg, err := results.NewDumpRegistry(resultsDir)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Contains("css.ch") {
		t.Fatal("css.ch should be in registry")
	}
}
