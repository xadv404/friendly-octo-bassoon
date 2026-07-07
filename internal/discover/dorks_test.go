package discover

import (
	"strings"
	"testing"
)

func TestDorkCounts(t *testing.T) {
	all := BuildVulnDorks("ch", false)
	fresh := BuildFreshDorks("ch", false)
	t.Logf("dorks: all=%d fresh=%d", len(all), len(fresh))
	if len(all) < 1500 {
		t.Fatalf("expected 1500+ tight dorks, got %d", len(all))
	}
	if len(all) > 6000 {
		t.Fatalf("dork set unexpectedly large: %d", len(all))
	}
}

func TestBuildVulnDorks_SwissWideBroad(t *testing.T) {
	dorks := BuildVulnDorks("ch", false)
	if len(dorks) < 1500 {
		t.Fatalf("expected 1500+ dorks, got %d", len(dorks))
	}

	for _, d := range dorks {
		if strings.Contains(d, "site:.ch") {
			t.Fatalf("wide mode must not use site:.ch: %s", d)
		}
		if strings.Contains(d, "inurl:? ") && !strings.Contains(d, "inurl:?id=") &&
			!strings.Contains(d, "inurl:?pid=") && !strings.Contains(d, "inurl:?D1=") &&
			!strings.Contains(d, "inurl:?num=") && !strings.Contains(d, "inurl:?objekt_id=") {
			t.Fatalf("dork too broad (bare inurl:?): %s", d)
		}
		if strings.HasSuffix(strings.TrimSpace(d), "inurl:?") {
			t.Fatalf("dork ends with bare inurl:?: %s", d)
		}
	}

	mustHave := []string{
		"inurl:product.php inurl:?id=",
		"inurl:promo.php inurl:?id=",
		"inurl:immobilier inurl:detail.php inurl:?id=",
		"inurl:RegionRef inurl:.php inurl:?id=",
		"inurl:Kauf-Suche.php inurl:?id=",
		"inurl:news_view.php inurl:?id=",
	}
	for _, want := range mustHave {
		found := false
		for _, d := range dorks {
			if strings.Contains(d, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing dork containing %q in %d dorks", want, len(dorks))
		}
	}

	forbidden := []string{"index.php?id=", "sql syntax", "ext:php inurl:?", "inurl:login.php"}
	for _, d := range dorks {
		lower := strings.ToLower(d)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Fatalf("forbidden pattern in dork: %s", d)
			}
		}
	}
}

func TestBuildFreshDorks(t *testing.T) {
	fresh := BuildFreshDorks("ch", false)
	if len(fresh) < 60 {
		t.Fatalf("expected 60+ fresh dorks, got %d", len(fresh))
	}
	for _, d := range fresh {
		if strings.Contains(d, "site:.ch") {
			t.Fatalf("fresh dork must not use site:.ch: %s", d)
		}
	}
	mustHave := []string{
		"inurl:product.php inurl:?id=",
		"inurl:Kauf-Suche.php inurl:?id=",
		"inurl:RegionRef inurl:.php inurl:?id=",
	}
	for _, want := range mustHave {
		found := false
		for _, d := range fresh {
			if strings.Contains(d, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing fresh dork containing %q", want)
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
		"https://shop.ch/wp-content/plugins/foo/?id=1",
	}
	out := filterDiscoveryURLs(in, false)
	if len(out) != 2 {
		t.Fatalf("got %v", out)
	}
}

func TestDorkNoAutoExclusions(t *testing.T) {
	d := BuildTopDorks("ch", false)[0]
	if strings.Contains(d, "-inurl:") {
		t.Fatalf("dork must not include -inurl exclusions: %s", d)
	}
}
