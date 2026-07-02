package discover

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	fhttp "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
)

const (
	googleConsentCookie = "YES+"
	googleSOCSCookie    = "CAESHAgBEhJnd3NfMjAyMzA4MTAtMF9SQzIaAmRlIAEaBgiAo_CmBg"
)

var googleTLSProfiles = []profiles.ClientProfile{
	profiles.Chrome_131,
	profiles.Chrome_133,
	profiles.Chrome_124,
}

func newGoogleTLSClient(attempt int) (tls_client.HttpClient, error) {
	jar := tls_client.NewCookieJar()
	profile := googleTLSProfiles[attempt%len(googleTLSProfiles)]
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(int(searchHTTPTimeout.Seconds())),
		tls_client.WithClientProfile(profile),
		tls_client.WithCookieJar(jar),
		tls_client.WithRandomTLSExtensionOrder(),
	}
	if pool := getProxyPool(); pool.hasProxies() {
		opts = append(opts, tls_client.WithProxyUrl(pool.first().String()))
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func resetGoogleTLSProxy(client tls_client.HttpClient) {
	if pool := getProxyPool(); pool.hasProxies() {
		_ = client.SetProxy(pool.first().String())
	}
}

func googleTLSGet(ctx context.Context, client tls_client.HttpClient, rawURL, referer string) (string, int, error) {
	req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	setGoogleTLSHeaders(req, referer)
	seedGoogleCookies(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

func googleTLSPost(ctx context.Context, client tls_client.HttpClient, rawURL, referer string, form url.Values) (string, int, error) {
	req, err := fhttp.NewRequestWithContext(ctx, fhttp.MethodPost, rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	setGoogleTLSHeaders(req, referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	seedGoogleCookies(req)

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", resp.StatusCode, err
	}
	return string(body), resp.StatusCode, nil
}

func seedGoogleCookies(req *fhttp.Request) {
	req.AddCookie(&fhttp.Cookie{Name: "CONSENT", Value: googleConsentCookie})
	req.AddCookie(&fhttp.Cookie{Name: "SOCS", Value: googleSOCSCookie})
}

func setGoogleTLSHeaders(req *fhttp.Request, referer string) {
	req.Header = fhttp.Header{
		"accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"},
		"accept-language":           {"fr-CH,fr;q=0.9,de-CH;q=0.8,de;q=0.7,en;q=0.4"},
		"cache-control":             {"max-age=0"},
		"sec-ch-ua":                 {`"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"`},
		"sec-ch-ua-mobile":          {"?0"},
		"sec-ch-ua-platform":        {`"Windows"`},
		"sec-fetch-dest":            {"document"},
		"sec-fetch-mode":            {"navigate"},
		"sec-fetch-user":            {"?1"},
		"upgrade-insecure-requests": {"1"},
		"user-agent":                {searchUserAgent},
		fhttp.HeaderOrderKey: {
			"accept",
			"accept-language",
			"cache-control",
			"sec-ch-ua",
			"sec-ch-ua-mobile",
			"sec-ch-ua-platform",
			"sec-fetch-dest",
			"sec-fetch-mode",
			"sec-fetch-site",
			"sec-fetch-user",
			"upgrade-insecure-requests",
			"user-agent",
			"referer",
		},
	}
	if referer == "" {
		req.Header.Set("sec-fetch-site", "none")
	} else {
		req.Header.Set("sec-fetch-site", "same-origin")
		req.Header.Set("referer", referer)
	}
}

func googleTLSWarmUp(ctx context.Context, client tls_client.HttpClient) error {
	urls := []string{
		googleHomeURL,
		"https://www.google.ch/ncr",
	}
	referer := ""
	for _, u := range urls {
		_, code, err := googleTLSGet(ctx, client, u, referer)
		if err != nil {
			return err
		}
		if code != fhttp.StatusOK && code != fhttp.StatusFound {
			return fmt.Errorf("google warmup HTTP %d", code)
		}
		referer = googleHomeURL
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(googleJitter(400 * time.Millisecond)):
		}
	}
	return nil
}
