package urllist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "urls.txt")
	content := `# scope
https://example.com/a?id=1

https://example.com/b?id=2
https://example.com/a?id=1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	urls, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 2 {
		t.Fatalf("expected 2 urls, got %d", len(urls))
	}
}

func TestLoad_InvalidURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(path, []byte("not-a-url\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoad_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# only comments\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}
