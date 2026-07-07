package discover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type mockFetcher struct {
	pages [][]string
}

func (m *mockFetcher) FetchPage(_ context.Context, _ string, _ bool, absolutePage, _ int) ([]string, error) {
	if absolutePage >= len(m.pages) {
		return nil, nil
	}
	return m.pages[absolutePage], nil
}

type mockDorkFetcher struct {
	mockFetcher
	fresh map[string][]string
}

func (m *mockDorkFetcher) FetchDork(_ context.Context, dork string, start int) ([]string, error) {
	if start != 0 || m.fresh == nil {
		return nil, nil
	}
	return m.fresh[dork], nil
}

func TestRun_KeepsSwissURLsWithParams(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	fetcher := &mockFetcher{pages: [][]string{{
		"https://css.ch/page.php?id=1",
		"https://css.ch/static/about",
		"https://www.example.com/page.php?id=2",
		"https://css.ch/$.array-fill",
		"http://css.ch:80/product.php?cat=2",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:  "css.ch",
		Output:  out,
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
	for _, want := range []string{"page.php?id=1", "product.php?cat=2"} {
		if !containsAll(content, want) {
			t.Errorf("missing %q in:\n%s", want, content)
		}
	}
	for _, reject := range []string{"example.com", "static/about"} {
		if containsAll(content, reject) {
			t.Errorf("should reject %q", reject)
		}
	}
}

func TestRun_ManualPathFilter(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	fetcher := &mockFetcher{pages: [][]string{{
		"https://css.ch/devis.php?id=1",
		"https://css.ch/x.php?foo=1",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:  "css.ch",
		Output:  out,
		Paths:   []string{"devis"},
		Fetcher: fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 1 {
		t.Fatalf("kept %d want 1", result.Kept)
	}
}

func TestRun_NoFilter(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	fetcher := &mockFetcher{pages: [][]string{{
		"https://css.ch/a.php?id=1",
		"https://css.ch/b.php",
	}}}

	result, err := Run(context.Background(), Options{
		Domain:   "css.ch",
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

func TestRun_FreshPass(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	var viewDork string
	for _, d := range BuildFreshDorks("css.ch", false) {
		if strings.Contains(d, "view.php") {
			viewDork = d
			break
		}
	}
	if viewDork == "" {
		t.Fatal("no view.php fresh dork")
	}

	fetcher := &mockDorkFetcher{
		fresh: map[string][]string{
			viewDork: {"https://css.ch/view.php?id=1"},
		},
		mockFetcher: mockFetcher{pages: [][]string{
			{"https://css.ch/page.php?id=2"},
		}},
	}

	result, err := Run(context.Background(), Options{
		Domain:    "css.ch",
		Output:    out,
		Fetcher:   fetcher,
		FreshPass: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept != 2 {
		t.Fatalf("kept %d want 2", result.Kept)
	}
}

func TestRun_ContinuesAfterFetchErrorWhenHunt(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope.txt")

	result, err := Run(context.Background(), Options{
		Domain:     "ch",
		Output:     out,
		Source:     SourceGoogle,
		DorkSet:    DorkSetBig,
		CycleWeeks: 4,
		MaxPages:   3,
		Fetcher: &flakyFetcher{
			responses: []flakyResp{
				{urls: []string{"https://shop.ch/p.php?id=1"}},
				{err: fmt.Errorf("openserp HTTP 502")},
				{urls: []string{"https://shop.ch/item.php?x=1"}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept < 2 {
		t.Fatalf("kept %d want >=2", result.Kept)
	}
}

type flakyResp struct {
	urls []string
	err  error
}

type flakyFetcher struct {
	responses []flakyResp
}

func (f *flakyFetcher) FetchPage(_ context.Context, _ string, _ bool, absolutePage, _ int) ([]string, error) {
	if absolutePage >= len(f.responses) {
		return nil, nil
	}
	r := f.responses[absolutePage]
	return r.urls, r.err
}

func TestIsScannable_RejectsJunk(t *testing.T) {
	junk := []string{
		"https://css.ch/$.foo",
		"not-a-url",
		"https://css.ch/page",
		"https://example.com/page.php?id=1",
		"https://git.wsl.ch/EnviDat/ckan/-/blob/main/app.js?ref=tags",
		"https://shop.ch/assets/app.min.js?v=1",
		"https://shop.ch/static/style.css?x=1",
		"https://shop.ch/wp-content/plugins/foo/?id=1",
		"https://forum.ch/viewtopic.php?t=1",
		"https://school.ch/moodle/mod/url/view.php?id=1",
	}
	for _, u := range junk {
		if isScannable(u, true) {
			t.Errorf("should reject %q", u)
		}
	}
	if !isScannable("https://css.ch/page.php?id=1", true) {
		t.Error("valid Swiss URL rejected")
	}
}

func TestNormalizeSwissDomain(t *testing.T) {
	if got := NormalizeSwissDomain("css"); got != "css.ch" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeSwissDomain("www.CSS.CH"); got != "css.ch" {
		t.Fatalf("got %q", got)
	}
}

func TestNormalizeURL(t *testing.T) {
	got := normalizeURL("http://css.ch:80/devis.php?id=1")
	want := "http://css.ch/devis.php?id=1"
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
