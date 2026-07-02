package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSaveCursor(t *testing.T) {
	dir := t.TempDir()
	if p, err := LoadCursor(dir); err != nil || p != 0 {
		t.Fatalf("load empty: %d %v", p, err)
	}
	if err := SaveCursor(dir, 120); err != nil {
		t.Fatal(err)
	}
	p, err := LoadCursor(dir)
	if err != nil || p != 120 {
		t.Fatalf("got %d %v", p, err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "discover_cursor.json"))
	if len(data) == 0 {
		t.Fatal("cursor file missing")
	}
}

func TestDailyDorkOrder_Rotates(t *testing.T) {
	dorks := []string{"a", "b", "c", "d"}
	r1 := DailyDorkOrder(dorks, 0)
	r2 := DailyDorkOrder(dorks, 1)
	if len(r1) != 4 || r1[0] != "a" {
		t.Fatalf("seed 0: %v", r1)
	}
	if r2[0] != "b" || r2[3] != "a" {
		t.Fatalf("seed 1: %v", r2)
	}
}

func TestDaySeed(t *testing.T) {
	if DaySeed(99) != 99 {
		t.Fatal("custom seed")
	}
	if DaySeed(0) <= 0 {
		t.Fatal("auto seed")
	}
}
