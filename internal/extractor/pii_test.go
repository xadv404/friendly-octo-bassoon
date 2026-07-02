package extractor

import (
	"strings"
	"testing"
)

func validEmailRecord() PIIRecord {
	return PIIRecord{Email: "jean.dupont@bluewin.ch"}
}

func TestRecordMeetsMinimum(t *testing.T) {
	r := validEmailRecord()
	sanitizeRecord(&r)
	if !RecordMeetsMinimum(r) {
		t.Error("valid email should pass")
	}
	for _, p := range []PIIRecord{
		{},
		{Email: "noreply@css.ch"},
		{Email: "select@union.com"},
		{Email: "invalid"},
	} {
		sanitizeRecord(&p)
		if RecordMeetsMinimum(p) {
			t.Errorf("should reject %+v", p)
		}
	}
}

func TestHasMinimumPIIColumns(t *testing.T) {
	if !HasMinimumPIIColumns(map[PIIColumnKind]string{PIIEmail: "email"}) {
		t.Fatal("email column should pass")
	}
	if HasMinimumPIIColumns(map[PIIColumnKind]string{PIIPhone: "telefon"}) {
		t.Fatal("phone only should fail")
	}
}

func TestParseLabeledPII(t *testing.T) {
	raw := "nom=Meier|email=hans.meier@bluewin.ch|tel=0791234567"
	records := ParseLabeledPII(raw, "kunden")
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	if records[0].Email != "hans.meier@bluewin.ch" {
		t.Fatalf("email: %q", records[0].Email)
	}
}

func TestParseLabeledPII_EmailOnly(t *testing.T) {
	raw := "email=marie@sunrise.ch"
	if len(ParseLabeledPII(raw, "clients")) != 1 {
		t.Fatal("email-only should pass")
	}
}

func TestParseLabeledPII_PartialRejected(t *testing.T) {
	if len(ParseLabeledPII("nom=Dupont|tel=0791234567", "clients")) != 0 {
		t.Fatal("no email should be rejected")
	}
}

func TestScanPIIInText_NoSQL(t *testing.T) {
	body := `{"email":"user@bluewin.ch","telefon":"0791234567"}`
	records := ScanPIIInText(body)
	if len(records) != 1 || records[0].Email != "user@bluewin.ch" {
		t.Fatalf("got %+v", records)
	}
}

func TestPII_NoFalsePositives(t *testing.T) {
	safeBodies := []string{
		"XPATH syntax error: '~8.0.32-MySQL~'",
		"total: 847 items in database",
		`{"error":"invalid credentials"}`,
		`{"token":"eyJhbG","user":{"role":"admin"}}`,
		"SELECT * FROM users WHERE id=1",
		`email=select@union.com|tel=12345`,
	}
	for _, body := range safeBodies {
		if recs := ScanPIIInText(body); len(recs) > 0 {
			t.Errorf("false positive on %q: %+v", body, recs[0])
		}
	}
	if recs := ParseLabeledPII("email=noreply@css.ch", "users"); len(recs) > 0 {
		t.Error("noreply should be rejected")
	}
}

func TestFormatPIIRecord(t *testing.T) {
	s := FormatPIIRecord(validEmailRecord())
	if !strings.Contains(s, "email: jean.dupont@bluewin.ch") {
		t.Errorf("unexpected format:\n%s", s)
	}
	if strings.Contains(s, "nom:") || strings.Contains(s, "telephone:") {
		t.Error("should only contain email")
	}
}

func TestClassifyColumn(t *testing.T) {
	kind, ok := ClassifyColumn("email")
	if !ok || kind != PIIEmail {
		t.Fatalf("got %q %v", kind, ok)
	}
}

func TestSwissEmail(t *testing.T) {
	for _, e := range []string{"hans.meier@bluewin.ch", "a.b@canton-ge.ch"} {
		if !isValidEmail(e) {
			t.Errorf("valid email rejected: %s", e)
		}
	}
	for _, e := range []string{
		"admin@localhost", "test@example.com", "noreply@css.ch",
		"@invalid.ch", "a@", "select@union.com",
	} {
		if isValidEmail(e) {
			t.Errorf("invalid email accepted: %s", e)
		}
	}
}
