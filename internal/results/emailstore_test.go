package results

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadProviderEmails(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := "a@gmail.com\nb@gmail.com\nc@gmail.com\n"
	if err := os.WriteFile(filepath.Join(emailsDir, "gmail.com.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := ReadProviderEmails(dir, "gmail", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "a@gmail.com" || got[1] != "b@gmail.com" {
		t.Fatalf("got %v", got)
	}
}

func TestResolveProvider(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gmail.com.txt", "bluewin.ch.txt"} {
		if err := os.WriteFile(filepath.Join(emailsDir, name), []byte("x@test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	p, err := ResolveProvider(dir, "gmail")
	if err != nil || p != "gmail.com" {
		t.Fatalf("gmail: %q %v", p, err)
	}
	p, err = ResolveProvider(dir, "bluewin")
	if err != nil || p != "bluewin.ch" {
		t.Fatalf("bluewin: %q %v", p, err)
	}
}

func TestResolveProvider_YahooDomains(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"yahoo.ch.txt", "yahoo.com.txt"} {
		if err := os.WriteFile(filepath.Join(emailsDir, name), []byte("x@test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	p, err := ResolveProvider(dir, "yahoo.ch")
	if err != nil || p != "yahoo.ch" {
		t.Fatalf("yahoo.ch: %q %v", p, err)
	}
	p, err = ResolveProvider(dir, "yahoo.com")
	if err != nil || p != "yahoo.com" {
		t.Fatalf("yahoo.com: %q %v", p, err)
	}
	_, err = ResolveProvider(dir, "yahoo")
	if err == nil {
		t.Fatal("expected ambiguous error for yahoo")
	}
}

func TestResolveProvider_GmxDomains(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gmx.ch.txt", "gmx.com.txt"} {
		if err := os.WriteFile(filepath.Join(emailsDir, name), []byte("x@test\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	p, err := ResolveProvider(dir, "gmx.ch")
	if err != nil || p != "gmx.ch" {
		t.Fatalf("gmx.ch: %q %v", p, err)
	}
	p, err = ResolveProvider(dir, "gmx.com")
	if err != nil || p != "gmx.com" {
		t.Fatalf("gmx.com: %q %v", p, err)
	}
	_, err = ResolveProvider(dir, "gmx")
	if err == nil {
		t.Fatal("expected ambiguous error for gmx")
	}
}

func TestListProviders(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emailsDir, "icloud.com.txt"), []byte("a@icloud.com\nb@icloud.com\n"), 0644); err != nil {
		t.Fatal(err)
	}

	list, err := ListProviders(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Provider != "icloud.com" || list[0].Count != 2 {
		t.Fatalf("got %+v", list)
	}
}

func TestParseEmailRequest(t *testing.T) {
	cases := []struct {
		in       string
		count    int
		provider string
		ok       bool
	}{
		{"100 gmail", 100, "gmail", true},
		{"gmail 50", 50, "gmail", true},
		{"gmail", 0, "", false},
		{"abc gmail", 0, "", false},
	}
	for _, tc := range cases {
		c, p, ok := ParseEmailRequest(tc.in)
		if ok != tc.ok || c != tc.count || p != tc.provider {
			t.Errorf("%q => (%d,%q,%v) want (%d,%q,%v)", tc.in, c, p, ok, tc.count, tc.provider, tc.ok)
		}
	}
}

func TestReadProviderEmails_Format(t *testing.T) {
	dir := t.TempDir()
	emailsDir := filepath.Join(dir, "emails")
	if err := os.MkdirAll(emailsDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(emailsDir, "gmail.com.txt"), []byte("user@gmail.com\n"), 0644); err != nil {
		t.Fatal(err)
	}
	emails, err := ReadProviderEmails(dir, "gmail.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(emails) != 1 || strings.Contains(emails[0], "email:") {
		t.Fatalf("got %v", emails)
	}
}
