package discover

import (
	"strings"
	"testing"
)

func TestBuildVulnDorks_SwissWideBroad(t *testing.T) {
	dorks := BuildVulnDorks("ch", false)
	if len(dorks) < 150 {
		t.Fatalf("expected 150+ broad dorks, got %d", len(dorks))
	}

	for _, d := range dorks {
		if !strings.Contains(d, "site:.ch") {
			t.Fatalf("dork must lock Switzerland: %s", d)
		}
	}

	mustHave := []string{
		"site:.ch inurl:?",
		"site:.ch ext:php inurl:?",
		"site:.ch inurl:?id=",
		"site:.ch inurl:promo.php inurl:?",
		"site:.ch inurl:kanton inurl:?",
		"site:.ch inurl:?ID=",
		"site:.ch inurl:immobilier inurl:detail.php inurl:?",
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
	if len(fresh) < 50 {
		t.Fatalf("expected 50+ fresh dorks, got %d", len(fresh))
	}
	for _, d := range fresh {
		if !strings.Contains(d, "site:.ch") {
			t.Fatalf("fresh dork must lock Switzerland: %s", d)
		}
	}
	mustHave := []string{
		"site:.ch inurl:view.php inurl:?",
		"site:.ch inurl:promo.php inurl:?",
		"site:.ch inurl:immobilier inurl:detail.php inurl:?",
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
