package discover

import "testing"

func TestParseGoogleResults_URLq(t *testing.T) {
	html := `<a href="/url?q=https%3A%2F%2Fshop.example.ch%2Fpage.php%3Fid%3D1&amp;sa=U">`
	urls := parseGoogleResults(html)
	if len(urls) != 1 || urls[0] != "https://shop.example.ch/page.php?id=1" {
		t.Fatalf("got %v", urls)
	}
}
