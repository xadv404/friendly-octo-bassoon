package alert

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestRenderBoardDiscoverFreshPass(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Title:    "Weekly lancé",
		Subtitle: "🇨🇭 Max emails .ch · 6525 dorks DBMS\n📊 Limite : ∞ URLs",
		Phase:    "fresh-pass",
		DorkStep: 21,
		DorkTotal: 78,
		Kept:     8,
		Fetched:  15,
		Skipped:  4,
		URLsList: []string{
			"https://shop.example.ch/page.php?id=1",
			"https://news.site.ch/article.php?id=3",
		},
	})
	if text == "" {
		t.Fatal("empty board")
	}
	if !containsAll(text, "SQLi Hunter", "Weekly", "🔍 DÉCOUVERTE", "⚡ Fresh pass", "21/78", "📌 8 URLs", "🔗 shop.example.ch", "Dernières URLs") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderBoardScanWithVulns(t *testing.T) {
	text := RenderBoard("fr", BoardState{
		Title:        "Daily lancé",
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
	if !containsAll(text, "🛡 SCAN", "Vulnérabilités", "example.ch", "120/500", "💥") {
		t.Fatalf("unexpected board:\n%s", text)
	}
}

func TestRenderBoardMonthlyTitle(t *testing.T) {
	text := RenderBoard("fr", BoardState{Title: "Monthly lancé"})
	if !contains(text, "📅") {
		t.Fatalf("expected monthly emoji:\n%s", text)
	}
}

func TestProgressBar(t *testing.T) {
	bar := progressBar(5, 10)
	if len([]rune(bar)) != 14 {
		t.Fatalf("bar wrong length: %q (%d runes)", bar, len([]rune(bar)))
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
