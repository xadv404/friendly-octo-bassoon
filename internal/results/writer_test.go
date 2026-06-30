package results

import (
	"os"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestDomainFromURL(t *testing.T) {
	d, err := DomainFromURL("https://www.Example.COM/path?id=1")
	if err != nil {
		t.Fatal(err)
	}
	if d != "www.example.com" {
		t.Fatalf("got %q", d)
	}
}

func TestWriteSites(t *testing.T) {
	dir := t.TempDir()
	targets := []TargetResult{{
		URL: "https://target.com/page?id=1",
		Findings: []models.Finding{{
			URL: "https://target.com/page?id=1", Parameter: "id",
			VulnType: models.SQLiError, Confidence: models.Confirmed,
			Payload: "'",
		}},
		Extractions: []models.ExtractedData{{
			FindingURL: "https://target.com/page?id=1", Parameter: "id",
			DataType: models.DataVersion, Value: "8.0.32-MySQL",
		}},
		DurationMs: 100,
	}}

	written, err := WriteSites(dir, "test", targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 2 {
		t.Fatalf("expected 2 files, got %d", len(written))
	}

	jsonPath := dir + "/target.com/target.com.json"
	sqlPath := dir + "/target.com/target.com.sql"
	for _, p := range written {
		if p != jsonPath && p != sqlPath {
			t.Fatalf("unexpected path %s", p)
		}
	}
}

func TestWriteSites_GroupsByDomain(t *testing.T) {
	dir := t.TempDir()
	targets := []TargetResult{
		{URL: "https://shop.com/a?id=1", Findings: []models.Finding{{VulnType: models.SQLiError}}},
		{URL: "https://shop.com/b?id=2", Findings: []models.Finding{{VulnType: models.SQLiUnion}}},
	}
	_, err := WriteSites(dir, "test", targets)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(dir + "/shop.com/shop.com.json"); err != nil {
		t.Fatal("expected single merged report for shop.com")
	}
}
