package discover

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	tls_client "github.com/bogdanfinn/tls-client"
)

var reGoogleSEI = regexp.MustCompile(`(?i)enablejs\?sei=([a-zA-Z0-9_-]+)`)

func followGoogleEnableJS(ctx context.Context, client tls_client.HttpClient, html, searchURL, referer string) (string, error) {
	m := reGoogleSEI.FindStringSubmatch(html)
	if len(m) < 2 {
		return "", fmt.Errorf("google: sei enablejs introuvable")
	}
	base := "https://www.google.ch"
	if strings.Contains(searchURL, "google.com") {
		base = "https://www.google.com"
	}
	ejURL := fmt.Sprintf("%s/httpservice/retry/enablejs?sei=%s&biw=1920&bih=969", base, m[1])
	_, code, err := googleTLSGet(ctx, client, ejURL, searchURL)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("google enablejs HTTP %d", code)
	}
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-time.After(googleJitter(600 * time.Millisecond)):
	}
	body, code, err := googleTLSGet(ctx, client, searchURL, referer)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("google enablejs retry HTTP %d", code)
	}
	return body, nil
}

func tryGoogleConsentDL(ctx context.Context, client tls_client.HttpClient, searchURL, referer string) (string, error) {
	u, err := url.Parse("https://consent.google.ch/dl")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("continue", searchURL)
	q.Set("gl", "CH")
	q.Set("hl", "fr")
	q.Set("cm", "2")
	q.Set("pc", "srp")
	q.Set("uxe", "none")
	q.Set("src", "1")
	u.RawQuery = q.Encode()

	body, code, err := googleTLSGet(ctx, client, u.String(), referer)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("google consent dl HTTP %d", code)
	}
	if isGoogleConsentPage(body) {
		return acceptGoogleConsent(ctx, client, body, u.String())
	}
	return body, nil
}
