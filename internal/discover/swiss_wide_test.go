package discover

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRun_VulnHuntWide(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope_ch.txt")

	fetcher := &mockFetcher{pages: [][]string{{
		"https://shop-unknown.ch/product.php?id=1",
		"https://random-site.ch/page.php?uid=2",
		"https://example.com/page.php?id=3",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:  "ch",
		Output:  out,
		Limit:   10,
		Source:  SourceBing,
		Fetcher: fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 2 {
		t.Fatalf("kept %d want 2 (.ch with params only)", result.Kept)
	}
}

func TestRun_WaybackWideRejected(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Domain: "ch",
		Source: SourceWayback,
	})
	if err == nil {
		t.Fatal("wayback wide should fail")
	}
}
