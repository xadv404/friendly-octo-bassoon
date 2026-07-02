package discover

import "testing"

func TestParseVQD(t *testing.T) {
	html := `<form><input name="vqd" value="3-abc123xyz"></form>`
	if got := parseVQD(html); got != "3-abc123xyz" {
		t.Fatalf("got %q", got)
	}
}

func TestParseDDGResults_ResultLink(t *testing.T) {
	html := `<a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fshop.ch%2Fpage.php%3Fid%3D1">`
	urls := parseDDGResults(html)
	if len(urls) != 1 || urls[0] != "https://shop.ch/page.php?id=1" {
		t.Fatalf("got %v", urls)
	}
}

func TestUnwrapDDGLink(t *testing.T) {
	raw := "//duckduckgo.com/l/?uddg=https%3A%2F%2Fadmin.ch%2Ffr"
	got := unwrapDDGLink(raw)
	if got != "https://admin.ch/fr" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildDDGForm_FirstPage(t *testing.T) {
	form := buildDDGForm("site:.ch", 0, "")
	if form.Get("b") != "" || form.Get("vqd") != "" {
		t.Fatalf("got %v", form)
	}
	if form.Get("kl") != "de-ch" {
		t.Fatal("kl")
	}
}

func TestBuildDDGForm_NextPage(t *testing.T) {
	form := buildDDGForm("site:.ch", 10, "vqd-token")
	if form.Get("vqd") != "vqd-token" || form.Get("s") != "10" || form.Get("dc") != "11" {
		t.Fatalf("got %v", form)
	}
}
