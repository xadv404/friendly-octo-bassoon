//go:build integration

package discover

import (
	"context"
	"os"
	"regexp"
	"testing"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

var reGoogleSEI = regexp.MustCompile(`enablejs\?sei=([a-zA-Z0-9_-]+)`)

func TestGoogleEnableJSRetry(t *testing.T) {
	if os.Getenv("DISCOVER_PROXY") == "" {
		t.Skip("DISCOVER_PROXY non configuré")
	}
	ReloadProxyPool()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for i := 0; i < 8; i++ {
		client, _ := newGoogleTLSClient()
		if i > 0 {
			resetGoogleTLSProxy(client)
		}
		_ = googleTLSWarmUp(ctx, client)
		searchURL, _ := buildGoogleSearchURL(googleSearchStrategies()[0], "site:.ch inurl:id=", 0)
		html, code, _ := googleTLSGet(ctx, client, searchURL, googleHomeURL)
		t.Logf("initial %d: code=%d len=%d enablejs=%v", i+1, code, len(html), isGoogleEnableJS(html))
		if code != 200 || !isGoogleEnableJS(html) {
			continue
		}
		m := reGoogleSEI.FindStringSubmatch(html)
		if len(m) < 2 {
			continue
		}
		sei := m[1]
		ejURL := "https://www.google.ch/httpservice/retry/enablejs?sei=" + sei + "&biw=1920&bih=969"
		_, c1, _ := googleTLSGet(ctx, client, ejURL, searchURL)
		t.Logf("enablejs follow: code=%d", c1)
		time.Sleep(500 * time.Millisecond)
		html2, code2, _ := googleTLSGet(ctx, client, searchURL, googleHomeURL)
		urls := parseGoogleResults(html2)
		t.Logf("retry: code=%d len=%d urlq=%d enablejs=%v", code2, len(html2), len(urls), isGoogleEnableJS(html2))
		if len(urls) > 0 {
			t.Log(urls[0])
			return
		}
	}
	t.Fatal("enablejs retry failed")
}

func TestGoogleConsentTLS(t *testing.T) {
	if os.Getenv("DISCOVER_PROXY") == "" {
		t.Skip("DISCOVER_PROXY non configuré")
	}
	ReloadProxyPool()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	for i := 0; i < 8; i++ {
		client, _ := newGoogleTLSClient()
		if i > 0 {
			resetGoogleTLSProxy(client)
		}
		_ = googleTLSWarmUp(ctx, client)
		searchURL, _ := buildGoogleSearchURL(googleSearchStrategies()[0], "site:.ch inurl:php?id=", 0)
		html, code, _ := googleTLSGet(ctx, client, searchURL, googleHomeURL)
		if !isGoogleConsentPage(html) {
			t.Logf("shot %d: code=%d consent=false", i+1, code)
			continue
		}
		html2, err := acceptGoogleConsent(ctx, client, html, searchURL)
		urls := parseGoogleResults(html2)
		t.Logf("consent %d: err=%v urlq=%d enablejs=%v", i+1, err, len(urls), isGoogleEnableJS(html2))
		if len(urls) > 0 {
			return
		}
	}
	t.Fatal("consent flow failed")
}

// keep one-shot helper
func TestGoogleTLSOneShot(t *testing.T) {
	if os.Getenv("DISCOVER_PROXY") == "" {
		t.Skip("DISCOVER_PROXY non configuré")
	}
	ReloadProxyPool()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	for i := 0; i < 10; i++ {
		var client tls_client.HttpClient
		client, _ = newGoogleTLSClient()
		if i > 0 {
			resetGoogleTLSProxy(client)
		}
		_ = googleTLSWarmUp(ctx, client)
		searchURL, _ := buildGoogleSearchURL(googleSearchStrategies()[0], "site:.ch inurl:id=", 0)
		html, code, err := googleTLSGet(ctx, client, searchURL, googleHomeURL)
		t.Logf("shot %d: code=%d err=%v len=%d consent=%v enablejs=%v urlq=%d",
			i+1, code, err, len(html), isGoogleConsentPage(html), isGoogleEnableJS(html),
			len(parseGoogleResults(html)))
		if code == 200 && len(parseGoogleResults(html)) > 0 {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatal("aucun résultat en 10 essais")
}
