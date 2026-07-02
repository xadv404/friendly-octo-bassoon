package discover

import "testing"

func TestParseSerpAPIResults(t *testing.T) {
	resp := serpAPIResponse{
		OrganicResults: []serpAPIOrganic{
			{Link: "https://shop.example.ch/page.php?id=1"},
			{
				Link: "https://www.admin.ch/fr",
				Sitelinks: &serpAPISitelinks{
					Inline: []struct {
						Link string `json:"link"`
					}{{Link: "https://www.admin.ch/de"}},
				},
			},
			{Link: "https://www.google.com/search?q=test"},
		},
	}
	urls := parseSerpAPIResults(resp)
	if len(urls) != 3 {
		t.Fatalf("got %d urls: %v", len(urls), urls)
	}
}

func TestUseSerpAPI(t *testing.T) {
	t.Setenv("SERPAPI_API_KEY", "")
	if UseSerpAPI() {
		t.Fatal("expected false")
	}
	t.Setenv("SERPAPI_API_KEY", "abc123")
	if !UseSerpAPI() {
		t.Fatal("expected true")
	}
}

func TestGoogleBackendLabel(t *testing.T) {
	t.Setenv("SERPAPI_API_KEY", "key")
	if got := GoogleBackendLabel(); got != "google (SerpAPI)" {
		t.Fatalf("got %q", got)
	}
}
