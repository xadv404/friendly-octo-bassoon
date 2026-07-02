package discover

import (
	"context"
	"path/filepath"
	"testing"
)

func TestRun_SwissWideMode(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "scope_ch.txt")

	fetcher := &domainMockFetcher{byDomain: map[string][][]string{
		"swisscom.ch": {{
			"https://www.swisscom.ch/shop?id=1",
			"https://www.swisscom.ch/static",
		}},
		"migros.ch": {{
			"https://www.migros.ch/product?pid=42",
		}},
		"css.ch": {{
			"https://www.css.ch/page?id=9",
		}},
	}}

	result, err := Run(context.Background(), Options{
		Domain:  "ch",
		Output:  out,
		Limit:   10,
		Fetcher: fetcher,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Kept < 2 {
		t.Fatalf("kept %d want at least 2", result.Kept)
	}
}

// domainMockFetcher route FetchPage par domaine.
type domainMockFetcher struct {
	byDomain map[string][][]string
}

func (m *domainMockFetcher) FetchPage(_ context.Context, domain string, _ bool, page, _ int) ([]string, error) {
	pages, ok := m.byDomain[domain]
	if !ok || page >= len(pages) {
		return nil, nil
	}
	return pages[page], nil
}

func TestSwissSeedDomains_OnlyCH(t *testing.T) {
	if len(SwissSeedDomains()) < 20 {
		t.Fatal("expected substantial seed list")
	}
	for _, d := range SwissSeedDomains() {
		if len(d) < 4 || d[len(d)-3:] != ".ch" {
			t.Errorf("non .ch domain in seeds: %q", d)
		}
	}
}
