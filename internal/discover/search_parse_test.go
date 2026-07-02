package discover

import "testing"

func TestParseGoogleResults(t *testing.T) {
	html := `<a href="/url?q=https://shop.ch/page.php?id=1&amp;sa=U">x</a>`
	urls := parseGoogleResults(html)
	if len(urls) != 1 || !containsStr(urls[0], "shop.ch/page.php?id=1") {
		t.Fatalf("got %v", urls)
	}
}

func TestParseDDGResults(t *testing.T) {
	html := `href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Ftest.ch%2Fp.php%3Fid%3D1"`
	urls := parseDDGResults(html)
	if len(urls) != 1 || urls[0] != "https://test.ch/p.php?id=1" {
		t.Fatalf("got %v", urls)
	}
}

func TestIsSearchBlocked(t *testing.T) {
	if !isSearchBlocked("<html>captcha verify</html>") {
		t.Fatal("expected blocked")
	}
	if isSearchBlocked("<html>results</html>") {
		t.Fatal("expected ok")
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
