package discover

import (
	"strings"
	"testing"
)

func TestBuildTopDorks(t *testing.T) {
	top := BuildTopDorks("ch", false)
	if len(top) < 80 || len(top) > 250 {
		t.Fatalf("expected 80-250 top dorks, got %d", len(top))
	}
	big := BuildBigDorks("ch", false)
	if len(top) >= len(big) {
		t.Fatalf("top set must be smaller than big: %d vs %d", len(top), len(big))
	}
	vuln := BuildVulnDorks("ch", false)
	if len(top) >= len(vuln) {
		t.Fatalf("top set must be smaller than vuln: %d vs %d", len(top), len(vuln))
	}

	for _, d := range top {
		if strings.Contains(d, "intext:mysql") || strings.Contains(d, "intext:ODBC") {
			t.Fatalf("top dorks must not include DBMS signatures: %s", d)
		}
		if strings.Contains(d, "site:.ch") {
			t.Fatalf("wide mode must not use site:.ch: %s", d)
		}
	}

	mustHave := []string{
		"inurl:product.php inurl:?id=",
		"inurl:newsletter inurl:.php inurl:?id=",
		"inurl:RegionRef inurl:.php inurl:?id=",
		"inurl:immobilier inurl:detail.php inurl:?id=",
	}
	for _, want := range mustHave {
		found := false
		for _, d := range top {
			if strings.Contains(d, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing top dork containing %q", want)
		}
	}
}

func TestBuildTopDorks_OnePerLine(t *testing.T) {
	for _, d := range BuildTopDorks("ch", false) {
		if strings.Contains(d, "\n") {
			t.Fatalf("dork contains newline: %q", d)
		}
	}
}
