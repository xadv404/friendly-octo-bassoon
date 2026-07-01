package extractor

import (
	"strings"
	"testing"
)

func TestClassifyColumn(t *testing.T) {
	cases := []struct {
		col  string
		kind PIIColumnKind
	}{
		{"email", PIIEmail},
		{"user_email", PIIEmail},
		{"telefon", PIIPhone},
		{"natel", PIIPhone},
		{"nom", PIINom},
		{"nachname", PIINom},
		{"vorname", PIIPrenom},
		{"geburtsdatum", PIIDOB},
		{"strasse", PIIAddress},
		{"plz", PIIAddress},
		{"iban", PIIIBAN},
	}
	for _, c := range cases {
		kind, ok := ClassifyColumn(c.col)
		if !ok || kind != c.kind {
			t.Errorf("ClassifyColumn(%q) = %q,%v want %q", c.col, kind, ok, c.kind)
		}
	}
	// Faux positifs colonnes
	for _, col := range []string{"username", "filename", "table_name", "is_mail_sent"} {
		if kind, ok := ClassifyColumn(col); ok && kind == PIINom {
			t.Errorf("column %q should not classify as nom", col)
		}
	}
}

func TestIsUserTable(t *testing.T) {
	if !IsUserTable("users") || !IsUserTable("kunden") || !IsUserTable("versicherte") {
		t.Fatal("expected user tables")
	}
	for _, tbl := range []string{"orders", "products", "sessions", "migrations"} {
		if IsUserTable(tbl) {
			t.Errorf("%q should not be user table", tbl)
		}
	}
}

func TestRecordMeetsMinimum(t *testing.T) {
	r := PIIRecord{Email: "hans.meier@bluewin.ch"}
	sanitizeRecord(&r)
	if !RecordMeetsMinimum(r) {
		t.Error("valid email should pass")
	}
	r = PIIRecord{Phone: "0791234567"}
	sanitizeRecord(&r)
	if !RecordMeetsMinimum(r) {
		t.Error("valid CH phone should pass")
	}
	r = PIIRecord{Nom: "Meier", Prenom: "Hans"}
	sanitizeRecord(&r)
	if RecordMeetsMinimum(r) {
		t.Error("name only should fail")
	}
}

func TestParseLabeledPII(t *testing.T) {
	raw := "nom=Meier|prenom=Hans|email=hans.meier@bluewin.ch|tel=0791234567|naissance=1985-03-12|adresse=Bahnhofstrasse 1, 8001 Zürich|iban=CH9300762011623852957"
	records := ParseLabeledPII(raw, "kunden")
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	r := records[0]
	if r.Nom != "Meier" || r.Email != "hans.meier@bluewin.ch" || r.Phone == "" {
		t.Fatalf("incomplete record: %+v", r)
	}
	if r.IBAN == "" {
		t.Fatal("valid iban should be captured")
	}
}

func TestParseLabeledPII_WithoutIBAN(t *testing.T) {
	raw := "nom=Dupont|prenom=Marie|email=marie@sunrise.ch|tel=+41791234567"
	records := ParseLabeledPII(raw, "clients")
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	if records[0].IBAN != "" {
		t.Fatal("iban should be empty")
	}
}

func TestScanPIIInText_NoSQL(t *testing.T) {
	body := `{"nachname":"Meier","vorname":"Hans","email":"user@bluewin.ch","telefon":"0791234567","strasse":"Bahnhofstrasse 1, 8001 Zürich"}`
	records := ScanPIIInText(body)
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	if records[0].Email != "user@bluewin.ch" {
		t.Fatalf("email: %q", records[0].Email)
	}
}

func TestPII_NoFalsePositives(t *testing.T) {
	// Aucun email ni téléphone CH valide → 0 enregistrement
	safeBodies := []string{
		"XPATH syntax error: '~8.0.32-MySQL~'",
		"total: 847 items in database",
		`{"error":"invalid credentials"}`,
		`{"token":"eyJhbG","user":{"role":"admin"}}`,
		"SELECT * FROM users WHERE id=1",
		"null",
		"have results",
		`nom=admin|email=admin@localhost`,
		`tel=12345|email=test@example.com`,
		`iban=FR7630006000011234567890189|email=test@example.com`,
		`iban=CH0000000000000000000|email=noreply@css.ch`,
		`nom=select|prenom=union|email=error@syntax.com`,
		`tel=0999999999|email=invalid`,
		"044123",
		"version 14.10 PostgreSQL",
		`email=select@union.com|tel=12345`,
	}
	for _, body := range safeBodies {
		if recs := ScanPIIInText(body); len(recs) > 0 {
			t.Errorf("false positive on %q: %+v", body, recs[0])
		}
	}
	// noreply + tel invalide
	if recs := ParseLabeledPII("nom=admin|email=noreply@css.ch|tel=0999999999", "users"); len(recs) > 0 {
		t.Error("noreply + invalid phone should be rejected")
	}
	// Noms SQL rejetés, email+tel valides conservés
	if recs := ParseLabeledPII("nom=Error|prenom=Syntax|email=hans@bluewin.ch|tel=0791234567", "users"); len(recs) != 1 {
		t.Fatal("valid email+phone should pass")
	} else if recs[0].Nom != "" || recs[0].Prenom != "" {
		t.Errorf("SQL-ish names should be stripped: %+v", recs[0])
	}
	// IBAN invalide ignoré, enregistrement conservé sans iban
	if recs := ParseLabeledPII("email=marie@sunrise.ch|tel=0791112233|iban=CH0000000000000000000", "users"); len(recs) != 1 {
		t.Fatal("valid contact without iban should pass")
	} else if recs[0].IBAN != "" {
		t.Error("invalid iban should be stripped")
	}
}

func TestSwissPhone(t *testing.T) {
	for _, p := range []string{"0791234567", "+41 79 123 45 67", "044 123 45 67", "0041 79 123 45 67"} {
		if !isValidPhone(p) {
			t.Errorf("expected valid CH phone %q", p)
		}
	}
	for _, p := range []string{"0612345678", "+33612345678", "0999999999", "12345", "802.11", "8.0.32"} {
		if isValidPhone(p) {
			t.Errorf("expected invalid phone %q", p)
		}
	}
}

func TestSwissIBAN(t *testing.T) {
	if !isValidIBAN("CH9300762011623852957") {
		t.Fatal("valid CH IBAN rejected")
	}
	for _, ib := range []string{
		"FR7630006000011234567890189",
		"CH0000000000000000000",
		"CH93OOO76O011623852957",
		"CH93",
	} {
		if isValidIBAN(ib) {
			t.Errorf("invalid IBAN accepted: %s", ib)
		}
	}
}

func TestSwissEmail(t *testing.T) {
	valid := []string{"hans.meier@bluewin.ch", "a.b@canton-ge.ch"}
	for _, e := range valid {
		if !isValidEmail(e) {
			t.Errorf("valid email rejected: %s", e)
		}
	}
	invalid := []string{
		"admin@localhost", "test@example.com", "noreply@css.ch",
		"@invalid.ch", "a@", "a@b", "select@union.com",
	}
	for _, e := range invalid {
		if isValidEmail(e) {
			t.Errorf("invalid email accepted: %s", e)
		}
	}
}

func TestSwissNames(t *testing.T) {
	for _, n := range []string{"Meier", "Dupont-Jones", "Müller"} {
		if !isValidName(n) {
			t.Errorf("valid name rejected: %s", n)
		}
	}
	for _, n := range []string{"null", "select", "admin", "error", "x", "1234"} {
		if isValidName(n) {
			t.Errorf("invalid name accepted: %s", n)
		}
	}
}

func TestSwissDOB(t *testing.T) {
	if !isValidDOB("1985-03-12") {
		t.Error("valid dob rejected")
	}
	for _, d := range []string{"2099-01-01", "1850-01-01", "invalid", "99-99-99"} {
		if isValidDOB(d) {
			t.Errorf("invalid dob accepted: %s", d)
		}
	}
}

func TestSwissAddress(t *testing.T) {
	if !isValidAddress("Bahnhofstrasse 1, 8001 Zürich") {
		t.Error("valid address rejected")
	}
	if !isValidAddress("8001 Zürich") {
		t.Error("NPA+city should pass")
	}
	for _, a := range []string{"error", "select union", "short", "zurich"} {
		if isValidAddress(a) {
			t.Errorf("invalid address accepted: %q", a)
		}
	}
}

func TestFormatPIIRecord(t *testing.T) {
	s := FormatPIIRecord(PIIRecord{
		Nom: "Meier", Prenom: "Hans", Email: "hans@bluewin.ch", Phone: "0791234567",
		DOB: "1985-03-12", Address: "Bahnhofstrasse 1, 8001 Zürich", IBAN: "CH9300762011623852957",
	})
	for _, want := range []string{
		"nom: Meier", "prenom: Hans", "date_naissance: 1985-03-12",
		"adresse: Bahnhofstrasse 1, 8001 Zürich", "email: hans@bluewin.ch",
		"telephone: 0791234567", "iban: CH9300762011623852957",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func stringsContains(s, sub string) bool {
	return strings.Contains(s, sub)
}
