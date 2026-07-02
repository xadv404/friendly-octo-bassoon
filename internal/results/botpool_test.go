package results

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTakeEmailsForBot_DedupAndRemove(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "a@gmail.com\na@gmail.com\nb@gmail.com\nc@gmail.com\n"
	if err := os.WriteFile(filepath.Join(emailsDir, "gmail.com.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := TakeEmailsForBot(dir, "gmail", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Emails) != 2 || got.Emails[0] != "a@gmail.com" || got.Emails[1] != "b@gmail.com" {
		t.Fatalf("got %v", got.Emails)
	}

	left, _ := os.ReadFile(filepath.Join(emailsDir, "gmail.com.txt"))
	if string(left) != "c@gmail.com\n" {
		t.Fatalf("remaining: %q", left)
	}

	got2, err := TakeEmailsForBot(dir, "gmail", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got2.Emails) != 1 || got2.Emails[0] != "c@gmail.com" {
		t.Fatalf("second take: %v", got2.Emails)
	}

	got3, err := TakeEmailsForBot(dir, "gmail", 1)
	if err == nil {
		t.Fatalf("expected empty, got %v", got3.Emails)
	}

	delivered, _ := os.ReadFile(filepath.Join(dir, "bot_delivered.txt"))
	if !containsAll(string(delivered), "a@gmail.com", "b@gmail.com", "c@gmail.com") {
		t.Fatalf("delivered: %s", delivered)
	}
}

func TestCompactAllEmails_GlobalDedup(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(emailsDir, "gmail.com.txt"), []byte("dup@gmail.com\ndup@gmail.com\n"), 0644)
	_ = os.WriteFile(filepath.Join(emailsDir, "bluewin.ch.txt"), []byte("dup@gmail.com\nunique@bluewin.ch\n"), 0644)

	if err := CompactAllEmails(dir); err != nil {
		t.Fatal(err)
	}
	gmail, _ := os.ReadFile(filepath.Join(emailsDir, "gmail.com.txt"))
	if string(gmail) != "dup@gmail.com\n" {
		t.Fatalf("gmail: %q", gmail)
	}
	bluewin, _ := os.ReadFile(filepath.Join(emailsDir, "bluewin.ch.txt"))
	if string(bluewin) != "unique@bluewin.ch\n" {
		t.Fatalf("bluewin: %q", bluewin)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !stringsContains(s, p) {
			return false
		}
	}
	return true
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfSub(s, sub) >= 0)
}

func indexOfSub(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
