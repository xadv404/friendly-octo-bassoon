package results

import (
	"os"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestSiteStore_Streaming(t *testing.T) {
	dir := t.TempDir()
	store, err := NewSiteStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 100; i++ {
		tr := TargetResult{
			URL: "https://shop.com/p?id=" + fmtInt(i),
		}
		if i%10 == 0 {
			tr.Findings = []models.Finding{{VulnType: models.SQLiError, Parameter: "id"}}
		}
		if err := store.Add(tr); err != nil {
			t.Fatal(err)
		}
	}

	files, err := store.Finalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d", len(files))
	}
	if _, err := os.Stat(dir + "/shop.com/shop.com.json"); err != nil {
		t.Fatal(err)
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
