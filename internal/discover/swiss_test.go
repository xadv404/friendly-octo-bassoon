package discover

import "testing"

func TestIsSwissHost(t *testing.T) {
	for _, h := range []string{"css.ch", "www.css.ch", "api.shop.ch"} {
		if !IsSwissHost(h) {
			t.Errorf("expected Swiss host %q", h)
		}
	}
	for _, h := range []string{"", "example.com", "css.com", "notch"} {
		if IsSwissHost(h) {
			t.Errorf("expected non-Swiss host %q", h)
		}
	}
}

func TestIsSwissURL(t *testing.T) {
	if !IsSwissURL("https://www.css.ch/page?id=1") {
		t.Fatal("css.ch should pass")
	}
	if IsSwissURL("https://example.com/page?id=1") {
		t.Fatal("example.com should be rejected")
	}
}
