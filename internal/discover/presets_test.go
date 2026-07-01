package discover

import (
	"strings"
	"testing"
)

func TestParseList(t *testing.T) {
	got := ParseList(" id, ref ,policy ")
	if len(got) != 3 {
		t.Fatalf("got %v", got)
	}
}

func TestPresetNames(t *testing.T) {
	names := PresetNames()
	if len(names) < 2 {
		t.Fatal("expected presets")
	}
	if !strings.Contains(strings.Join(names, ","), "insurance") {
		t.Fatal("insurance preset missing")
	}
}
