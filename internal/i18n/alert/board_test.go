package alert

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestRenderBoardDiscoverFreshPass(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Phase:     "fresh-pass",
		DorkStep:  9,
		DorkTotal: 78,
		Kept:      0,
	})
	if !containsAll(text,
		"🎯 SQLi Hunter",
		"🔍 DÉCOUVERTE",
		"⚡ Fresh pass",
		"9/78 dorks",
		"📌 0 URLs",
		"🛡 SCAN",
		"⏳ En attente…",
	) {
		t.Fatalf("unexpected board:\n%s", text)
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
	if !containsAll(text, "🔗 Dernières URLs", "shop.ch") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderBoardScanWithVulns(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Phase:        "scan",
		DiscoverDone: true,
		DorkTotal:    78,
		DorkStep:     78,
		Kept:         45,
		Scanned:      120,
		ScanTotal:    500,
		Vulns:        3,
		Findings:     5,
		VulnsList: []models.Finding{
			{URL: "https://example.ch/page.php?id=1", Parameter: "id", VulnType: models.SQLiError},
		},
	})
	if !containsAll(text, "🛡 SCAN", "Vulnérabilités", "example.ch", "120/500") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestProgressBar(t *testing.T) {
	bar := progressBar(5, 10)
	if len([]rune(bar)) != 14 {
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
