package discover

import "testing"

func TestParseGoogleResults_URLq(t *testing.T) {
	html := `<a href="/url?q=https%3A%2F%2Fshop.example.ch%2Fpage.php%3Fid%3D1&amp;sa=U">`
	urls := parseGoogleResults(html)
	if len(urls) != 1 || urls[0] != "https://shop.example.ch/page.php?id=1" {
		t.Fatalf("got %v", urls)
	}
}

func TestParseGoogleResults_DirectCH(t *testing.T) {
	html := `cite>https://www.admin.ch/fr/accueil</cite>`
	urls := parseGoogleResults(html)
	if len(urls) != 1 {
		t.Fatalf("got %v", urls)
	}
}

func TestParseGoogleResults_JSON(t *testing.T) {
	html := `"url":"https://shop.example.ch/page.php?id=1"`
	urls := parseGoogleResults(html)
	if len(urls) != 1 || urls[0] != "https://shop.example.ch/page.php?id=1" {
		t.Fatalf("got %v", urls)
	}
}

func TestParseGoogleResults_JSONArray(t *testing.T) {
	html := `["https://www.test.ch/foo","",0]`
	urls := parseGoogleResults(html)
	if len(urls) != 1 || urls[0] != "https://www.test.ch/foo" {
		t.Fatalf("got %v", urls)
	}
}

func TestIsGoogleEnableJS(t *testing.T) {
	if !isGoogleEnableJS(`<meta content="0;url=/httpservice/retry/enablejs?sei=abc">`) {
		t.Fatal("enablejs should be detected")
	}
	if isGoogleHardBlocked(`<meta content="0;url=/httpservice/retry/enablejs?sei=abc">`) {
		t.Fatal("enablejs alone is not hard block")
	}
}
