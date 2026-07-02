package discover

import (
	"strings"
	"testing"
)

func TestBuildVulnDorks_SwissWideBroad(t *testing.T) {
	dorks := BuildVulnDorks("ch", false)
	if len(dorks) < 30 {
		t.Fatalf("expected many broad dorks, got %d", len(dorks))
	}

	for _, d := range dorks {
		if !strings.Contains(d, "site:.ch") {
			t.Fatalf("dork must lock Switzerland: %s", d)
		}
	}

	// Ultra-broad patterns for max coverage
	mustHave := []string{
		"site:.ch inurl:?",
		"site:.ch ext:php inurl:?",
		"site:.ch inurl:?id=",
	}
	for _, want := range mustHave {
		found := false
		for _, d := range dorks {
			if d == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing broad dork %q in %d dorks", want, len(dorks))
		}
	}

	// Pas de dorks CMS / chemins trop ciblés
	forbidden := []string{"joomla", "drupal", "wp-content", "index.php?id=", "sql syntax"}
	for _, d := range dorks {
		lower := strings.ToLower(d)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Fatalf("dork too narrow: %s", d)
			}
		}
	}
	if len(dorks) < 100 {
		t.Fatalf("expected 100+ daily dorks, got %d", len(dorks))
	}
}

func TestBuildVulnDorks_SingleDomain(t *testing.T) {
	dorks := BuildVulnDorks("shop.ch", false)
	if len(dorks) == 0 || !strings.HasPrefix(dorks[0], "site:shop.ch") {
		t.Fatalf("got %v", dorks[:1])
	}
}

func TestFilterSwissURLs(t *testing.T) {
	in := []string{
		"https://shop.ch/page.php?id=1",
		"https://example.com/page.php?id=2",
		"https://shop.ch/page.php?id=1",
	}
	out := filterSwissURLs(in)
	if len(out) != 1 || !strings.Contains(out[0], "shop.ch") {
		t.Fatalf("got %v", out)
	}
}
