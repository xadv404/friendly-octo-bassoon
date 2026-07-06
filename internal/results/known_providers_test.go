package results

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestIsKnownProvider(t *testing.T) {
	known := []string{
		"gmail.com", "bluewin.ch", "sunrise.ch", "gmx.ch", "yahoo.com",
		"hotmail.com", "outlook.com", "icloud.com", "proton.me",
	}
	for _, d := range known {
		if !IsKnownProvider(d) {
			t.Errorf("expected known: %s", d)
		}
	}
	rejected := []string{
		"phzh.ch", "eda.admin.ch", "admin.ch", "css.ch", "canton-ge.ch",
		"example.com", "shop.ch", "",
	}
	for _, d := range rejected {
		if IsKnownProvider(d) {
			t.Errorf("expected rejected: %s", d)
		}
	}
}

func TestEmailWriter_RejectsUnknownProvider(t *testing.T) {
	dir := t.TempDir()
	w, err := NewEmailWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, em := range []string{
		"user@phzh.ch",
		"admin@eda.admin.ch",
		"test@canton-ge.ch",
	} {
		if err := w.Append(em); err != nil {
			t.Fatal(err)
		}
	}
	if w.NewCount() != 0 {
		t.Fatalf("expected 0 new emails, got %d", w.NewCount())
	}
	if err := w.Append("valid@bluewin.ch"); err != nil {
		t.Fatal(err)
	}
	if w.NewCount() != 1 {
		t.Fatalf("expected 1 new email, got %d", w.NewCount())
	}
}

func TestEmailFromExtraction_KnownOnly(t *testing.T) {
	d := models.ExtractedData{
		DataType: models.DataPII,
		Value:    "user@phzh.ch\n",
	}
	if got := EmailFromExtraction(d); got != "" {
		t.Fatalf("expected reject, got %q", got)
	}
}

func TestCompactAllEmails_PurgesUnknownProviderFiles(t *testing.T) {
	dir := t.TempDir()
	emailsDir := EmailsDir(dir)
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emailsDir, "phzh.ch.txt"), []byte("a@phzh.ch\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emailsDir, "gmail.com.txt"), []byte("user@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := CompactAllEmails(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(emailsDir, "phzh.ch.txt")); !os.IsNotExist(err) {
		t.Fatal("phzh.ch.txt should be removed")
	}
	gmail, err := os.ReadFile(filepath.Join(emailsDir, "gmail.com.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(gmail), "user@gmail.com") {
		t.Fatalf("gmail kept: %q", gmail)
	}
}
