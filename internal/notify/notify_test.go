package notify

import "testing"

func TestNoop(t *testing.T) {
	var s Noop
	if s.Enabled() {
		t.Fatal("noop should be disabled")
	}
	s.Launch("x", "y")
	s.Error("z")
}

func TestParseAllowedIDs(t *testing.T) {
	ids := parseAllowedIDs(" 123 , 456 ")
	if len(ids) != 2 || ids[0] != 123 || ids[1] != 456 {
		t.Fatalf("got %v", ids)
	}
}

func TestStockSummaryEmpty(t *testing.T) {
	dir := t.TempDir()
	got := StockSummary(dir)
	if got != "stock emails: vide" {
		t.Fatalf("got %q", got)
	}
}
