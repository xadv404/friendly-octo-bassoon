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

func TestIsGoogleBlocked_EnableJS(t *testing.T) {
	if !isGoogleBlocked(`<meta content="0;url=/httpservice/retry/enablejs?sei=abc">`) {
		t.Fatal("enablejs should be blocked")
	}
}
