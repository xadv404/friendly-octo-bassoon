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
	n, err := ExportDorksFile(path, "ch", false, DorkSetBig)
	if err != nil {
		t.Fatal(err)
	}
	if n < 3500 {
		t.Fatalf("expected 3500+ dorks, got %d", n)
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
