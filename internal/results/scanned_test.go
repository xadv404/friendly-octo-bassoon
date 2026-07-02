package results

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScannedRegistry_MarkAndContains(t *testing.T) {
	dir := t.TempDir()
	reg, err := NewScannedRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	url := "https://shop.ch/page.php?id=1"
	if reg.Contains(url) {
		t.Fatal("should not be scanned yet")
	}
	if err := reg.Mark(url); err != nil {
		t.Fatal(err)
	}
	if !reg.Contains(url) {
		t.Fatal("should be scanned")
	}
	reg2, err := NewScannedRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reg2.Contains(url) {
		t.Fatal("should persist")
	}
}

func TestEmailWriter_LoadExistingDedup(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emailsDir, "gmail.com.txt"), []byte("a@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	w, err := NewEmailWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append("a@gmail.com"); err != nil {
		t.Fatal(err)
	}
	if w.NewCount() != 0 {
		t.Fatalf("expected 0 new, got %d", w.NewCount())
	}
	if err := w.Append("b@gmail.com"); err != nil {
		t.Fatal(err)
	}
	if w.NewCount() != 1 {
		t.Fatalf("expected 1 new, got %d", w.NewCount())
	}
}
