package discover

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportDorksFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dorks.txt")
	n, err := ExportDorksFile(path, "ch", false, DorkSetTop)
	if err != nil {
		t.Fatal(err)
	}
	if n < 80 || n > 250 {
		t.Fatalf("expected 80-250 top dorks, got %d", n)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != n {
		t.Fatalf("lines %d != count %d", len(lines), n)
	}
	if !strings.Contains(lines[0], "site:") && !strings.Contains(lines[0], "inurl:") {
		t.Fatalf("unexpected first dork: %q", lines[0])
	}
}
