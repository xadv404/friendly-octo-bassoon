package discover

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type mockFetcher struct {
	pages [][]string
}

func (m *mockFetcher) FetchPage(_ context.Context, _ string, _ bool, page, _ int) ([]string, error) {
	if page >= len(m.pages) {
		return nil, nil
	}
	return m.pages[page], nil
}

func TestRun_FiltersInsurancePreset(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	fetcher := &mockFetcher{pages: [][]string{{
		"https://assureur.com/devis.php?id=1",
		"https://assureur.com/static/about",
		"https://assureur.com/page.php?policy_id=42",
		"https://assureur.com/$.array-fill",
		"http://assureur.com:80/product.php?cat=2",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:  "assureur.com",
		Output:  out,
		Preset:  "insurance",
		Fetcher: fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 2 {
		t.Fatalf("kept %d want 2", result.Kept)
	}

	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{"devis.php?id=1", "policy_id=42"} {
		if !containsAll(content, want) {
			t.Errorf("missing %q in:\n%s", want, content)
		}
	}
	if containsAll(content, "static/about") {
		t.Error("static page should be filtered out")
	}
}

func TestRun_NoFilter(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	fetcher := &mockFetcher{pages: [][]string{{
		"https://target.com/a.php?id=1",
		"https://target.com/b.php",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:   "target.com",
		Output:   out,
		NoFilter: true,
		Fetcher:  fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 1 {
		t.Fatalf("kept %d want 1", result.Kept)
	}
}

func TestPassesFilters_PresetOR(t *testing.T) {
	opts := Options{Preset: "insurance", Paths: Presets["insurance"].Paths, Params: Presets["insurance"].Params}

	if !passesFilters("https://x.com/devis.php?id=1", opts) {
		t.Error("path match expected")
	}
	if !passesFilters("https://x.com/x.php?policy_id=1", opts) {
		t.Error("param match expected")
	}
	if passesFilters("https://x.com/x.php?foo=1", opts) {
		t.Error("no insurance signal should fail")
	}
}

func TestIsScannable_RejectsJunk(t *testing.T) {
	junk := []string{
		"https://x.com/$.foo",
		"not-a-url",
		"https://x.com/page",
	}
	for _, u := range junk {
		if isScannable(u) {
			t.Errorf("should reject %q", u)
		}
	}
	if !isScannable("https://x.com/page.php?id=1") {
		t.Error("valid URL rejected")
	}
}

func TestNormalizeURL(t *testing.T) {
	got := normalizeURL("http://assureur.com:80/devis.php?id=1")
	want := "http://assureur.com/devis.php?id=1"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func containsAll(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
