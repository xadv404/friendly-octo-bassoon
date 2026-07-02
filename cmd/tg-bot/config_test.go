package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAllowedIDs(t *testing.T) {
	m := parseAllowedIDs("123, 456 ,789")
	if len(m) != 3 || !m[123] || !m[456] || !m[789] {
		t.Fatalf("got %v", m)
	}
}

func TestLoadDotEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tg-bot.env")
	content := `# comment
TELEGRAM_BOT_TOKEN=test-token
TELEGRAM_ALLOWED_IDS=111222333
RESULTS_DIR=/tmp/emails
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Unsetenv("TELEGRAM_BOT_TOKEN")
	_ = os.Unsetenv("TELEGRAM_ALLOWED_IDS")
	_ = os.Unsetenv("RESULTS_DIR")

	if err := loadDotEnv(path); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("TELEGRAM_BOT_TOKEN") != "test-token" {
		t.Fatalf("token %q", os.Getenv("TELEGRAM_BOT_TOKEN"))
	}
	if os.Getenv("TELEGRAM_ALLOWED_IDS") != "111222333" {
		t.Fatalf("ids %q", os.Getenv("TELEGRAM_ALLOWED_IDS"))
	}
}

func TestLoadConfig_RequiresToken(t *testing.T) {
	_ = os.Unsetenv("TELEGRAM_BOT_TOKEN")
	dir := t.TempDir()
	path := filepath.Join(dir, "tg-bot.env")
	if err := os.WriteFile(path, []byte("TELEGRAM_ALLOWED_IDS=123\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Setenv("TG_BOT_ENV", path)
	t.Cleanup(func() {
		_ = os.Unsetenv("TG_BOT_ENV")
		_ = os.Unsetenv("TELEGRAM_BOT_TOKEN")
	})

	if _, err := loadConfig(); err == nil {
		t.Fatal("expected error without token")
	}
}
