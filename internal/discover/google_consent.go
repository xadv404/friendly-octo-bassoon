package discover

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	tls_client "github.com/bogdanfinn/tls-client"
)

var (
	reGoogleConsentTitle = regexp.MustCompile(`(?i)avant d.accéder|before you continue`)
	reGoogleConsentForm  = regexp.MustCompile(`(?is)<form[^>]+action="https://consent\.google[^"]+/save"[^>]*>.*?</form>`)
	reGoogleFormInput    = regexp.MustCompile(`(?i)<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"`)
)

func isGoogleConsentPage(html string) bool {
	if strings.Contains(html, "consent.google") && strings.Contains(html, "/save") {
		return true
	}
	return reGoogleConsentTitle.MatchString(html)
}

func acceptGoogleConsent(ctx context.Context, client tls_client.HttpClient, html, referer string) (string, error) {
	formHTML := extractGoogleAcceptForm(html)
	if formHTML == "" {
		return "", fmt.Errorf("google: formulaire consent introuvable")
	}

	data := url.Values{}
	for _, m := range reGoogleFormInput.FindAllStringSubmatch(formHTML, -1) {
		data.Set(m[1], m[2])
	}
	data.Set("set_eom", "false")
	data.Set("set_sc", "true")
	data.Set("set_aps", "true")
	data.Set("gl", "CH")

	action := "https://consent.google.ch/save"
	if strings.Contains(formHTML, "consent.google.com") {
		action = "https://consent.google.com/save"
	}

	body, code, err := googleTLSPost(ctx, client, action, referer, data)
	if err != nil {
		return "", err
	}
	if code == 429 || strings.Contains(body, "/sorry") {
		return body, fmt.Errorf("google: consent refusé HTTP %d", code)
	}
	if code >= 300 && code < 400 && data.Get("continue") != "" {
		body, code, err = googleTLSGet(ctx, client, data.Get("continue"), referer)
		if err != nil {
			return "", err
		}
	}
	if code != 200 {
		return body, fmt.Errorf("google consent HTTP %d", code)
	}
	return body, nil
}

func extractGoogleAcceptForm(html string) string {
	for _, m := range reGoogleConsentForm.FindAllString(html, -1) {
		if strings.Contains(m, `set_aps" value="true"`) || strings.Contains(m, "Tout accepter") {
			return m
		}
	}
	return ""
}
