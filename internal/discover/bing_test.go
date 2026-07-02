package discover

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildEmailDorks(t *testing.T) {
	dorks := BuildEmailDorks("css.ch", false)
	if len(dorks) < 20 {
		t.Fatalf("expected many dorks, got %d", len(dorks))
	}
	if !strings.Contains(dorks[0], "site:css.ch") {
		t.Fatalf("first dork: %s", dorks[0])
	}

	wide := BuildEmailDorks("ch", true)
	if len(wide) == 0 || !strings.Contains(wide[0], "site:.ch") {
		t.Fatalf("wide dorks: %v", wide[:1])
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

	client := newBingClient()
	client.baseURL = srv.URL
	client.delay = 0

	urls, err := client.FetchPage(context.Background(), "css.ch", false, 0, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(urls) != 1 || !strings.Contains(urls[0], "test.ch/page.php?id=42") {
		t.Fatalf("got %v", urls)
	}
}
