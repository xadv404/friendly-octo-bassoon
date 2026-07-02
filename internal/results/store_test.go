package results

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestSiteStore_Streaming(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSiteStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	store.AppendExtraction("https://shop.com/p?id=1", models.ExtractedData{
		DataType: models.DataPII,
		Value:    "alice@bluewin.ch\n",
	})
	store.AppendExtraction("https://shop.com/p?id=2", models.ExtractedData{
		DataType: models.DataPII,
		Value:    "bob@gmail.com\n",
	})

	for i := 0; i < 100; i++ {
		if err := store.Add(TargetResult{URL: "https://shop.com/p?id=" + fmtInt(i)}); err != nil {
			t.Fatal(err)
		}
	}

	files, err := store.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 email files, got %d: %v", len(files), files)
	}
	if _, err := os.Stat(filepath.Join(dir, "emails", "bluewin.ch.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "emails", "gmail.com.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "shop.com")); !os.IsNotExist(err) {
		t.Fatal("should not create per-target directory")
	}
}

func fmtInt(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
