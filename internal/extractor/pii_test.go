package extractor

import (
	"strings"
	"testing"
)

// completePIIRecord enregistrement valide avec tous les champs obligatoires.
func completePIIRecord() PIIRecord {
	return PIIRecord{
		Nom:     "Dupont",
		Prenom:  "Jean",
		DOB:     "1990-05-15",
		Address: "Bahnhofstrasse 1, 8001 Zürich",
		Email:   "jean.dupont@bluewin.ch",
		Phone:   "0791234567",
	}
}

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
	r := completePIIRecord()
	sanitizeRecord(&r)
	if !RecordMeetsMinimum(r) {
		t.Error("complete record should pass")
	}
	// IBAN optionnel
	r.IBAN = "CH9300762011623852957"
	sanitizeRecord(&r)
	if !RecordMeetsMinimum(r) {
		t.Error("complete record with iban should pass")
	}
	// Champs manquants → rejet
	partials := []PIIRecord{
		{Email: "a@b.ch", Phone: "0791234567"},
		{Nom: "Meier", Prenom: "Hans", Email: "a@b.ch", Phone: "0791234567"},
		{Nom: "Meier", Prenom: "Hans", DOB: "1985-01-01", Email: "a@b.ch", Phone: "0791234567"},
	}
	for i, p := range partials {
		sanitizeRecord(&p)
		if RecordMeetsMinimum(p) {
			t.Errorf("partial record %d should fail: %+v", i, p)
		}
	}
}

func TestHasMinimumPIIColumns(t *testing.T) {
	full := map[PIIColumnKind]string{
		PIINom: "nachname", PIIPrenom: "vorname", PIIDOB: "geburtsdatum",
		PIIAddress: "strasse", PIIEmail: "email", PIIPhone: "telefon",
	}
	if !HasMinimumPIIColumns(full) {
		t.Fatal("all required columns should pass")
	}
	partial := map[PIIColumnKind]string{PIIEmail: "email", PIIPhone: "telefon"}
	if HasMinimumPIIColumns(partial) {
		t.Fatal("email+phone only should not pass column check")
	}
}

func TestParseLabeledPII(t *testing.T) {
	raw := "nom=Meier|prenom=Hans|email=hans.meier@bluewin.ch|tel=0791234567|naissance=1985-03-12|adresse=Bahnhofstrasse 1, 8001 Zürich|iban=CH9300762011623852957"
	records := ParseLabeledPII(raw, "kunden")
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	r := records[0]
	if r.Nom == "" || r.Prenom == "" || r.DOB == "" || r.Address == "" || r.Email == "" || r.Phone == "" {
		t.Fatalf("incomplete record: %+v", r)
	}
	if r.IBAN == "" {
		t.Fatal("valid iban should be captured")
	}
}

func TestParseLabeledPII_WithoutIBAN(t *testing.T) {
	raw := "nom=Dupont|prenom=Marie|email=marie@sunrise.ch|tel=+41791234567|naissance=1990-05-15|adresse=Rue du Rhône 12, 1204 Genève"
	records := ParseLabeledPII(raw, "clients")
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	if records[0].IBAN != "" {
		t.Fatal("iban should be empty")
	}
}

func TestParseLabeledPII_PartialRejected(t *testing.T) {
	raw := "nom=Dupont|email=marie@sunrise.ch|tel=0791234567"
	if len(ParseLabeledPII(raw, "clients")) != 0 {
		t.Fatal("partial record should be rejected")
	}
}

func TestScanPIIInText_NoSQL(t *testing.T) {
	body := `{"nachname":"Meier","vorname":"Hans","email":"user@bluewin.ch","telefon":"0791234567","geburtsdatum":"1985-03-12","strasse":"Bahnhofstrasse 1, 8001 Zürich"}`
	records := ScanPIIInText(body)
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	r := records[0]
	if r.Nom == "" || r.Prenom == "" || r.DOB == "" || r.Address == "" {
		t.Fatalf("incomplete: %+v", r)
	}
}

func TestPII_NoFalsePositives(t *testing.T) {
	safeBodies := []string{
		"XPATH syntax error: '~8.0.32-MySQL~'",
		"total: 847 items in database",
		`{"error":"invalid credentials"}`,
		`{"token":"eyJhbG","user":{"role":"admin"}}`,
		"SELECT * FROM users WHERE id=1",
		`email=hans@bluewin.ch|tel=0791234567`,
		`nom=Dupont|email=marie@sunrise.ch|tel=0791234567`,
		`email=select@union.com|tel=12345`,
	}
	for _, body := range safeBodies {
		if recs := ScanPIIInText(body); len(recs) > 0 {
			t.Errorf("false positive on %q: %+v", body, recs[0])
		}
	}
	if recs := ParseLabeledPII("nom=admin|email=noreply@css.ch|tel=0999999999", "users"); len(recs) > 0 {
		t.Error("incomplete/invalid should be rejected")
	}
	if recs := ParseLabeledPII("nom=Error|prenom=Syntax|email=hans@bluewin.ch|tel=0791234567", "users"); len(recs) != 0 {
		t.Error("missing dob+address should be rejected")
	}
	if recs := ParseLabeledPII("nom=Meier|prenom=Hans|email=hans@bluewin.ch|tel=0791234567|naissance=1985-03-12|adresse=Bahnhofstrasse 1, 8001 Zürich|iban=CH0000000000000000000", "users"); len(recs) != 1 {
		t.Fatal("full record without valid iban should pass")
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
	for _, e := range []string{"hans.meier@bluewin.ch", "a.b@canton-ge.ch"} {
		if !isValidEmail(e) {
			t.Errorf("valid email rejected: %s", e)
		}
	}
	for _, e := range []string{
		"admin@localhost", "test@example.com", "noreply@css.ch",
		"@invalid.ch", "a@", "a@b", "select@union.com",
	} {
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
	s := FormatPIIRecord(completePIIRecord())
	for _, want := range []string{
		"nom: Dupont", "prenom: Jean", "date_naissance: 1990-05-15",
		"adresse: Bahnhofstrasse 1, 8001 Zürich", "email: jean.dupont@bluewin.ch",
		"telephone: 0791234567",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestFormatPIIRecord_WithIBAN(t *testing.T) {
	r := completePIIRecord()
	r.IBAN = "CH9300762011623852957"
	s := FormatPIIRecord(r)
	if !strings.Contains(s, "iban: CH9300762011623852957") {
		t.Error("iban should appear when present")
	}
}
