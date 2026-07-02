package discover

import "testing"

func TestIsGoogleConsentPage(t *testing.T) {
	html := `<title>Avant d'accéder à la recherche Google</title><form action="https://consent.google.ch/save">`
	if !isGoogleConsentPage(html) {
		t.Fatal("expected consent page")
	}
}

func TestExtractGoogleAcceptForm(t *testing.T) {
	html := `<form action="https://consent.google.ch/save" method="POST">
<input type="hidden" name="continue" value="https://www.google.ch/search?q=test">
<input type="hidden" name="set_aps" value="true">
<input type="submit" value="Tout accepter"></form>`
	form := extractGoogleAcceptForm(html)
	if form == "" {
		t.Fatal("expected accept form")
	}
}
