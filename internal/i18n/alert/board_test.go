package alert

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestRenderBoardDiscoverBig(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Phase:     "discover",
		DorkStep:  120,
		DorkTotal: 6525,
		Kept:      42,
	})
	if !containsAll(text, "120/6525", "42") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderBoardDiscoverFreshPass(t *testing.T) {
	text := RenderDiscoverBoard("fr", BoardState{
		Phase:     "fresh-pass",
		DorkStep:  9,
		DorkTotal: 78,
		Kept:      0,
	})
	if !containsAll(text, "9/78") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderScanBoardWaiting(t *testing.T) {
	text := RenderScanBoard("fr", BoardState{
		Phase:     "scan",
		ScanTotal: 500,
		Scanned:   0,
	})
	if !containsAll(text, "🛡", "0/500") {
		t.Fatalf("unexpected scan board:\n%s", text)
	}
}

func TestRenderBoardWithURLs(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Phase:     "fresh-pass",
		DorkStep:  20,
		DorkTotal: 78,
		Kept:      3,
		URLsList:  []string{"https://shop.ch/page.php?id=1"},
	})
	if !containsAll(text, "20/78") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderBoardScanWithVulns(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Phase:        "scan",
		Scanned:      120,
		ScanTotal:    500,
		Vulns:        3,
		Findings:     5,
		VulnsList: []models.Finding{
			{URL: "https://example.ch/page.php?id=1", Parameter: "id", VulnType: models.SQLiError},
		},
	})
	if !containsAll(text, "120/500", "🔴 3", "🔎 5") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderScanBoardStopped(t *testing.T) {
	text := RenderScanBoard("fr", BoardState{
		Phase:     "stopped",
		Scanned:   42,
		ScanTotal: 500,
		Vulns:     2,
		Findings:  3,
	})
	if !containsAll(text, "⏹", "42/500", "🔴 2") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderDiscoverBoardErrorKeepsProgress(t *testing.T) {
	text := RenderDiscoverBoard("fr", BoardState{
		Phase:     "error",
		Error:     "discover interrompu",
	})
	if !containsAll(text, "❌", "discover interrompu") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderDiscoverBoardStarting(t *testing.T) {
	text := RenderDiscoverBoard("fr", BoardState{
		Phase:     "discover",
		DorkTotal: 6525,
	})
	if !containsAll(text, "0/6525") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestProgressBar(t *testing.T) {
	bar := progressBar(5, 10)
	if len([]rune(bar)) != 10 {
		t.Fatalf("bar wrong length: %q", bar)
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
