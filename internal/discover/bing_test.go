package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildVulnDorks(t *testing.T) {
	dorks := BuildVulnDorks("ch", true)
	if len(dorks) < 30 {
		t.Fatalf("expected many dorks, got %d", len(dorks))
	}
	if !strings.Contains(dorks[0], "inurl:") {
		t.Fatalf("first dork: %s", dorks[0])
	}
	foundBroad := false
	for _, d := range dorks {
		if strings.Contains(d, "inurl:product.php inurl:?id=") {
			foundBroad = true
			break
		}
	}
	if !foundBroad {
		t.Fatal("missing tight dork inurl:product.php inurl:?id=")
	}
}

func TestParseBingResults(t *testing.T) {
	html := `
	<li class="b_algo">
	  <h2><a href="https://shop.ch/product.php?id=1">x</a></h2>
	  <cite>shop.ch/product.php?id=1</cite>
	</li>
	<a href="https://www.bing.com/search?q=foo">skip</a>
	`
	urls := parseBingResults(html)
	if len(urls) < 1 {
		t.Fatalf("got %v", urls)
	}
	found := false
	for _, u := range urls {
		if strings.Contains(u, "shop.ch/product.php?id=1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing shop url in %v", urls)
	}
}

func TestBingClient_FetchPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "" {
			t.Fatal("missing query")
		}
		w.Write([]byte(`<a href="https://test.ch/page.php?id=42"></a>`))
	}))
	defer srv.Close()

	client := newBingClient(42)
	client.baseURL = srv.URL
	client.delay = 0

	urls, err := client.FetchPage(context.Background(), "ch", false, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || !strings.Contains(urls[0], "test.ch/page.php?id=42") {
		t.Fatalf("got %v", urls)
	}
}
