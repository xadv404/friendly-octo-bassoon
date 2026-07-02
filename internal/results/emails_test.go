package results

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestEmailProvider(t *testing.T) {
	cases := map[string]string{
		"hans@bluewin.ch": "bluewin.ch",
		"user@gmail.com":  "gmail.com",
		"x@icloud.com":    "icloud.com",
		"bad":             "",
	}
	for email, want := range cases {
		if got := EmailProvider(email); got != want {
			t.Errorf("EmailProvider(%q) = %q want %q", email, got, want)
		}
	}
}

func TestEmailWriter_SeparateByProvider(t *testing.T) {
	dir := t.TempDir()
	w, err := NewEmailWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, em := range []string{
		"alice@bluewin.ch",
		"bob@bluewin.ch",
		"carol@gmail.com",
		"dan@icloud.com",
		"alice@bluewin.ch",
	} {
		if err := w.Append(em); err != nil {
			t.Fatal(err)
		}
	}
	files, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected 3 provider files, got %d: %v", len(files), files)
	}

	bluewin, _ := os.ReadFile(filepath.Join(dir, "emails", "bluewin.ch.txt"))
	if strings.Count(string(bluewin), "\n") != 2 {
		t.Fatalf("bluewin.ch.txt:\n%s", bluewin)
	}
	gmail, _ := os.ReadFile(filepath.Join(dir, "emails", "gmail.com.txt"))
	if !strings.Contains(string(gmail), "carol@gmail.com") {
		t.Fatalf("gmail.com.txt:\n%s", gmail)
	}
}

func TestWriteEmailsFromTargets(t *testing.T) {
	dir := t.TempDir()
	targets := []TargetResult{{
		URL: "https://x.ch/p?id=1",
		Extractions: []models.ExtractedData{{
			DataType: models.DataPII,
			Value:    "email: test@sunrise.ch\n",
		}},
	}}
	files, err := WriteEmailsFromTargets(dir, targets)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %v", files)
	}
}

func TestEmailFromExtraction(t *testing.T) {
	d := models.ExtractedData{
		DataType: models.DataPII,
		PII:      &models.PIIUser{Email: "a@hispeed.ch"},
	}
	if got := EmailFromExtraction(d); got != "a@hispeed.ch" {
		t.Fatalf("got %q", got)
	}
}
