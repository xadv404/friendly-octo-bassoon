package urllist

import "testing"

func TestIsCHHost(t *testing.T) {
	for host, want := range map[string]bool{
		"shop.example.ch": true,
		"www.admin.ch":    true,
		"example.com":     false,
		"forum.opsi.org":  false,
	} {
		if got := IsCHHost(host); got != want {
			t.Fatalf("%s: got %v want %v", host, got, want)
		}
	}
}

func TestFilterCH(t *testing.T) {
	urls := []string{
		"https://shop.ch/a",
		"https://forum.opsi.org/b",
		"https://www.bvsga.ch/Wil/?id=1",
	}
	kept, dropped := FilterCH(urls)
	if len(kept) != 2 || len(dropped) != 1 {
		t.Fatalf("kept=%d dropped=%d", len(kept), len(dropped))
	}
}
