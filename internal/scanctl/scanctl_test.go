package scanctl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeTier(t *testing.T) {
	tier, err := normalizeTier("monthly")
	if err != nil || tier != TierMonthly {
		t.Fatalf("got %q %v", tier, err)
	}
	tier, err = normalizeTier("big")
	if err != nil || tier != TierWeekly {
		t.Fatalf("got %q %v", tier, err)
	}
	if _, err := normalizeTier("daily"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseStarted(t *testing.T) {
	tier, pid, log := ParseStarted("STARTED weekly pid=4242 log=results/weekly.log")
	if tier != "weekly" || pid != "4242" || log != "results/weekly.log" {
		t.Fatalf("got %q %q %q", tier, pid, log)
	}
}

func TestRootFromResultsDir(t *testing.T) {
	dir := t.TempDir()
	results := filepath.Join(dir, "results")
	if err := os.MkdirAll(results, 0755); err != nil {
		t.Fatal(err)
	}
	if got := Root(results); got != dir {
		t.Fatalf("got %q want %q", got, dir)
	}
}

func TestStartMissingScript(t *testing.T) {
	dir := t.TempDir()
	_, err := Start(filepath.Join(dir, "results"), "weekly")
	if err == nil {
		t.Fatal("expected error")
	}
}
