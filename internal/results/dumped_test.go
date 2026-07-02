package results

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDumpRegistry_MarkAndContains(t *testing.T) {
	dir := t.TempDir()
	reg, err := NewDumpRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Contains("css.ch") {
		t.Fatal("should not be dumped yet")
	}
	if err := reg.Mark("css.ch"); err != nil {
		t.Fatal(err)
	}
	if !reg.Contains("css.ch") {
		t.Fatal("should be dumped")
	}

	reg2, err := NewDumpRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reg2.Contains("css.ch") {
		t.Fatal("should persist across reload")
	}
	data, _ := os.ReadFile(filepath.Join(dir, "dumped_domains.txt"))
	if !strings.Contains(string(data), "css.ch") {
		t.Fatalf("file: %s", data)
	}
}
