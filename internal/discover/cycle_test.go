package discover

import "testing"

func TestClampCycleWeeks(t *testing.T) {
	if ClampCycleWeeks(0) != 1 || ClampCycleWeeks(5) != 4 || ClampCycleWeeks(3) != 3 {
		t.Fatal("clamp failed")
	}
}

func TestMaxPagesPerRun(t *testing.T) {
	total := 6525
	if got := MaxPagesPerRun(4, total); got != 1632 {
		t.Fatalf("4 weeks: got %d want 1632", got)
	}
	if got := MaxPagesPerRun(1, total); got != 6525 {
		t.Fatalf("1 week: got %d", got)
	}
	if MaxPagesPerRun(2, 0) != 0 {
		t.Fatal("zero dorks")
	}
}
