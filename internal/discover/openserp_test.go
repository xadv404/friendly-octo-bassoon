package discover

import (
	"testing"
)

func TestParseOpenSerpResults(t *testing.T) {
	resp := openSerpResponse{}
	resp.Data.Results = []openSerpResult{
		{Link: "https://shop.example.ch/page.php?id=1"},
		{Link: "https://www.google.com/search?q=test"},
		{Link: "https://www.admin.ch/fr"},
	}
	urls := parseOpenSerpResults(resp)
	if len(urls) != 2 {
		t.Fatalf("got %d urls: %v", len(urls), urls)
	}
}

func TestUseOpenSerp(t *testing.T) {
	t.Setenv("OPENSERP_API_KEY", "")
	if UseOpenSerp() {
		t.Fatal("expected false")
	}
	t.Setenv("OPENSERP_API_KEY", "osk_test123")
	if !UseOpenSerp() {
		t.Fatal("expected true")
	}
}

func TestGoogleBackendLabel_OpenSerp(t *testing.T) {
	t.Setenv("OPENSERP_API_KEY", "osk_test")
	if got := GoogleBackendLabel(); got != "google (OpenSerp API)" {
		t.Fatalf("got %q", got)
	}
}
