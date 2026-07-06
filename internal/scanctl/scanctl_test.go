package scanctl

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeTier(t *testing.T) {
	tier, err := normalizeTier("hunt")
	if err != nil || tier != TierHunt {
		t.Fatalf("got %q %v", tier, err)
	}
	tier, err = normalizeTier("weekly")
	if err != nil || tier != TierHunt {
		t.Fatalf("weekly alias: %q %v", tier, err)
	}
	if _, err := normalizeTier("daily"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseStarted(t *testing.T) {
	tier, pid, log := ParseStarted("STARTED hunt pid=4242 log=results/hunt.log")
	if tier != "hunt" || pid != "4242" || log != "results/hunt.log" {
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
	_, err := Start(filepath.Join(dir, "results"), "hunt")
	if err == nil {
		t.Fatal("expected error")
	}
}
