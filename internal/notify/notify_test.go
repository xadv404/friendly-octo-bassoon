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

func TestStockSummaryUsesI18n(t *testing.T) {
	dir := t.TempDir()
	got := StockSummary(dir)
	if got == "" {
		t.Fatal("expected non-empty")
	}
}
