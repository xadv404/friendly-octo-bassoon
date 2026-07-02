package extractor

import "testing"

var goldenPositiveEmail = []struct {
	name string
	raw  string
}{
	{"labeled", "email=hans.meier@bluewin.ch"},
	{"with noise fields", "nom=Meier|prenom=Hans|email=marie@sunrise.ch|tel=0791234567"},
	{"json body", `{"email":"user@bluewin.ch","telefon":"0791234567"}`},
}

var goldenNegativeEmail = []struct {
	name string
	body string
}{
	{"mysql error", "XPATH syntax error: '~8.0.32-MySQL~'"},
	{"no email", `{"telefon":"0791234567"}`},
	{"noreply", "email=noreply@css.ch"},
	{"sql keyword", "email=select@union.com"},
	{"invalid", "email=not-an-email"},
}

func TestGolden_EmailPositive(t *testing.T) {
	for _, tc := range goldenPositiveEmail {
		t.Run(tc.name, func(t *testing.T) {
			var recs []PIIRecord
			if stringsHasPrefix(tc.raw, "{") {
				recs = ScanPIIInText(tc.raw)
			} else {
				recs = ParseLabeledPII(tc.raw, "users")
			}
			if len(recs) != 1 || recs[0].Email == "" {
				t.Fatalf("expected email, got %+v", recs)
			}
		})
	}
}

func TestGolden_EmailNegative(t *testing.T) {
	for _, tc := range goldenNegativeEmail {
		t.Run(tc.name, func(t *testing.T) {
			if recs := ScanPIIInText(tc.body); len(recs) > 0 {
				t.Fatalf("FP: %+v", recs[0])
			}
			if recs := ParseLabeledPII(tc.body, "users"); len(recs) > 0 {
				t.Fatalf("FP: %+v", recs[0])
			}
		})
	}
}

func stringsHasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
