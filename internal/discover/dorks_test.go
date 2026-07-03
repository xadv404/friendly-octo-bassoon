package discover

import (
	"strings"
	"testing"
)

func TestDorkCounts(t *testing.T) {
	all := BuildVulnDorks("ch", false)
	fresh := BuildFreshDorks("ch", false)
	t.Logf("dorks: all=%d fresh=%d", len(all), len(fresh))
	if len(all) > 3500 {
		t.Fatalf("dork set unexpectedly large: %d", len(all))
	}
}

func TestBuildVulnDorks_SwissWideBroad(t *testing.T) {
	dorks := BuildVulnDorks("ch", false)
	if len(dorks) < 2000 {
		t.Fatalf("expected 2000+ broad dorks, got %d", len(dorks))
	}

	for _, d := range dorks {
		if strings.Contains(d, "site:.ch") {
			t.Fatalf("wide mode must not use site:.ch (country=CH on OpenSerp): %s", d)
		}
	}

	mustHave := []string{
		"inurl:?",
		"ext:php inurl:?",
		"inurl:?id=",
		"inurl:promo.php inurl:?",
		"inurl:kanton inurl:?",
		"inurl:?ID=",
		"inurl:immobilier inurl:detail.php inurl:?",
		"inurl:product.php inurl:?id=",
		"inurl:RegionRef inurl:.php inurl:?",
		"inurl:Gemeinde- inurl:.php inurl:?",
		"inurl:Kauf-Suche.php inurl:?",
		"inurl:news_view.php inurl:?id=",
		"(inurl:id= | inurl:pid= | inurl:cat=) inurl:&",
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
			t.Fatalf("missing dork %q in %d dorks", want, len(dorks))
		}
	}

	forbidden := []string{"joomla", "drupal", "wp-content", "index.php?id=", "sql syntax"}
	for _, d := range dorks {
		lower := strings.ToLower(d)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Fatalf("dork too narrow: %s", d)
			}
		}
	}
}

func TestBuildFreshDorks(t *testing.T) {
	fresh := BuildFreshDorks("ch", false)
	if len(fresh) < 150 {
		t.Fatalf("expected 150+ fresh dorks, got %d", len(fresh))
	}
	for _, d := range fresh {
		if strings.Contains(d, "site:.ch") {
			t.Fatalf("fresh dork must not use site:.ch: %s", d)
		}
	}
	mustHave := []string{
		"inurl:view.php inurl:?",
		"inurl:promo.php inurl:?",
		"inurl:immobilier inurl:detail.php inurl:?",
		"inurl:product.php inurl:?id=",
		"inurl:Kauf-Suche.php inurl:?",
		"inurl:RegionRef inurl:.php inurl:?",
	}
	for _, want := range mustHave {
		found := false
		for _, d := range fresh {
			if d == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing fresh dork %q", want)
		}
	}
	all := BuildVulnDorks("ch", false)
	if len(all) <= len(fresh) {
		t.Fatalf("full dork set should be larger than fresh set: %d vs %d", len(all), len(fresh))
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

func TestFilterDiscoveryURLs_CountryWide(t *testing.T) {
	in := []string{
		"https://shop.ch/page.php?id=1",
		"https://swiss-example.com/product.php?id=2",
		"https://example.com/static/page",
	}
	out := filterDiscoveryURLs(in, false)
	if len(out) != 2 {
		t.Fatalf("got %v", out)
	}
}
