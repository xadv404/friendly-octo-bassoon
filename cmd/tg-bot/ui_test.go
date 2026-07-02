package main

import "testing"

func TestProviderEmoji(t *testing.T) {
	cases := map[string]string{
		"gmail.com":  "📧",
		"bluewin.ch": "📬",
		"gmx.ch":     "✉️",
		"yahoo.com":  "💌",
		"unknown.ch": "📮",
	}
	for prov, want := range cases {
		if got := providerEmoji(prov); got != want {
			t.Errorf("%s => %q want %q", prov, got, want)
		}
	}
}

func TestStockMessageEmpty(t *testing.T) {
	msg := stockMessage(config{resultsDir: t.TempDir()})
	if msg == "" || !contains(msg, "vide") {
		t.Fatalf("got %q", msg)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
