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

func TestIsSwissWide(t *testing.T) {
	for _, d := range []string{"ch", ".ch", "*", "suisse", "swiss", "all"} {
		if !IsSwissWide(d) {
			t.Errorf("expected wide mode for %q", d)
		}
	}
	if IsSwissWide("css.ch") {
		t.Error("css.ch should not be wide mode")
	}
}

func TestNormalizeSwissDomainWide(t *testing.T) {
	if got := NormalizeSwissDomain("css"); got != "css.ch" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeSwissDomain("ch"); got != "ch" {
		t.Fatalf("got %q want ch", got)
	}
	if got := NormalizeSwissDomain("suisse"); got != "ch" {
		t.Fatalf("got %q want ch", got)
	}
}
