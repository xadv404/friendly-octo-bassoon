package alert

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestRenderBoardDiscoverFreshPass(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Title:         "Daily lancé",
		Subtitle:      "discover: Suisse",
		Phase:         "fresh-pass",
		DiscoverLabel: "fresh-pass",
		DorkStep:      12,
		DorkTotal:     53,
		Kept:          8,
		Fetched:       120,
		Skipped:       4,
	})
	if text == "" {
		t.Fatal("empty board")
	}
	if !containsAll(text, "sqli-hunter", "fresh-pass", "12/53", "8 gardées") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderBoardScanWithVulns(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Title:        "Daily lancé",
		Phase:        "scan",
		DiscoverDone: true,
		DorkTotal:    53,
		DorkStep:     53,
		Kept:         45,
		Scanned:      120,
		ScanTotal:    500,
		Vulns:        3,
		Findings:     5,
		VulnsList: []models.Finding{
			{URL: "https://example.ch/page.php?id=1", Parameter: "id", VulnType: "error"},
		},
	})
	if !containsAll(text, "Vulnérabilités", "error", "example.ch", "120/500") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestProgressBar(t *testing.T) {
	bar := progressBar(5, 10)
	if len(bar) < 18 {
		t.Fatalf("bar too short: %q", bar)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !contains(s, p) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
