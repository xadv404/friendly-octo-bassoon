package discover

import (
	"strings"
	"testing"
)

func TestBuildBigDorks(t *testing.T) {
	big := BuildBigDorks("ch", false)
	vuln := BuildVulnDorks("ch", false)
	t.Logf("dorks: big=%d vuln=%d", len(big), len(vuln))

	if len(big) <= len(vuln) {
		t.Fatalf("big set should be larger than vuln: %d vs %d", len(big), len(vuln))
	}
	if len(big) < 3500 {
		t.Fatalf("expected 3500+ big dorks, got %d", len(big))
	}

	dbmsMustHave := []string{
		"intext:mysql_fetch",
		`intext:"Microsoft OLE DB"`,
		`intext:"PostgreSQL"`,
		`intext:"ORA-"`,
		`intext:"Microsoft JET"`,
		"intext:sqlite_master",
		"intext:org.hsqldb",
		"intext:com.informix",
		"intext:FrontBase",
		"intext:org.apache.derby",
		"intext:ibase_",
		"intext:cloudflare",
		"intext:maxdb",
		"intext:virtuoso",
	}
	for _, want := range dbmsMustHave {
		found := false
		for _, d := range big {
			if strings.Contains(strings.ToLower(d), strings.ToLower(want)) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing DBMS/WAF pattern %q in big dorks", want)
		}
	}

	for _, d := range big {
		if strings.Contains(d, "sql syntax") {
			t.Fatalf("forbidden sql syntax in big dork: %s", d)
		}
	}
}

func TestWeekSeed(t *testing.T) {
	if WeekSeed(99) != 99 {
		t.Fatal("custom week seed")
	}
	if WeekSeed(0) <= 0 {
		t.Fatal("week seed should be positive")
	}
}

func TestLoadSaveCursorBig(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCursorKind(dir, CursorBig, 77); err != nil {
		t.Fatal(err)
	}
	p, err := LoadCursorKind(dir, CursorBig)
	if err != nil || p != 77 {
		t.Fatalf("got page %d err %v", p, err)
	}
	pDaily, _ := LoadCursor(dir)
	if pDaily != 0 {
		t.Fatalf("daily cursor should be separate, got %d", pDaily)
	}
	if err := SaveCursorKind(dir, CursorMonthly, 200); err != nil {
		t.Fatal(err)
	}
	pm, _ := LoadCursorKind(dir, CursorMonthly)
	if pm != 200 {
		t.Fatalf("monthly cursor got %d", pm)
	}
}

func TestLoadSaveCursorHunt(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCursorKind(dir, CursorHunt, 42); err != nil {
		t.Fatal(err)
	}
	p, err := LoadCursorKind(dir, CursorHunt)
	if err != nil || p != 42 {
		t.Fatalf("hunt cursor: %d %v", p, err)
	}
}

func TestLoadCursorHuntMigratesFromBig(t *testing.T) {
	dir := t.TempDir()
	if err := SaveCursorKind(dir, CursorBig, 99); err != nil {
		t.Fatal(err)
	}
	p, err := LoadCursorKind(dir, CursorHunt)
	if err != nil || p != 99 {
		t.Fatalf("migration: got %d %v", p, err)
	}
}

func TestDefaultMaxPagesVuln(t *testing.T) {
	if DefaultMaxPages(DorkSetVuln) != 400 {
		t.Fatal("vuln daily pages")
	}
}
