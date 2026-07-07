package results

import (
	"os"
	"path/filepath"
	"strings"
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
		}},
		Extractions: []models.ExtractedData{{
			FindingURL: "https://target.com/page?id=1", Parameter: "id",
			DataType: models.DataPII, Value: "user@bluewin.ch\n",
		}},
	}}

	written, err := WriteSites(dir, "test", targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 1 {
		t.Fatalf("expected 1 email file, got %d: %v", len(written), written)
	}

	data, err := os.ReadFile(filepath.Join(dir, "emails", "bluewin.ch.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "user@bluewin.ch") {
		t.Fatalf("unexpected content: %s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "target.com")); !os.IsNotExist(err) {
		t.Fatal("should not create per-target directory")
	}
}

func TestWriteSites_NoEmails(t *testing.T) {
	dir := t.TempDir()
	targets := []TargetResult{{
		URL: "https://target.com/page?id=1",
		Findings: []models.Finding{{
			VulnType: models.SQLiError,
		}},
		Extractions: []models.ExtractedData{{
			DataType: models.DataVersion, Value: "8.0.32-MySQL",
		}},
	}}
	written, err := WriteSites(dir, "test", targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 0 {
		t.Fatalf("expected no files without emails, got %v", written)
	}
}
