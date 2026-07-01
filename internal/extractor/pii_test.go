package extractor

import "testing"

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
}

func TestIsUserTable(t *testing.T) {
	if !IsUserTable("users") || !IsUserTable("kunden") || !IsUserTable("versicherte") {
		t.Fatal("expected user tables")
	}
	if IsUserTable("orders") || IsUserTable("products") {
		t.Fatal("orders/products should not match")
	}
}

func TestRecordMeetsMinimum(t *testing.T) {
	if !RecordMeetsMinimum(PIIRecord{Email: "jean@test.ch"}) {
		t.Error("email only should pass")
	}
	if !RecordMeetsMinimum(PIIRecord{Phone: "0791234567"}) {
		t.Error("CH phone only should pass")
	}
	if RecordMeetsMinimum(PIIRecord{Nom: "Meier", Prenom: "Hans"}) {
		t.Error("name only should fail")
	}
}

func TestParseLabeledPII(t *testing.T) {
	raw := "nom=Meier|prenom=Hans|email=hans.meier@bluewin.ch|tel=0791234567|naissance=1985-03-12|adresse=8001 Zürich|iban=CH9300762011623852957"
	records := ParseLabeledPII(raw, "kunden")
	if len(records) != 1 {
		t.Fatalf("got %d records", len(records))
	}
	r := records[0]
	if r.Nom != "Meier" || r.Email != "hans.meier@bluewin.ch" || r.Phone == "" {
		t.Fatalf("incomplete record: %+v", r)
	}
	if r.IBAN == "" {
		t.Fatal("iban should be captured when present")
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

func TestHasMinimumPIIColumns(t *testing.T) {
	cols := map[PIIColumnKind]string{PIINom: "nachname", PIIPrenom: "vorname"}
	if HasMinimumPIIColumns(cols) {
		t.Fatal("nom+prenom without email/phone should fail")
	}
	cols[PIIEmail] = "email"
	if !HasMinimumPIIColumns(cols) {
		t.Fatal("with email should pass")
	}
}

func TestFormatPIIRecord(t *testing.T) {
	s := FormatPIIRecord(PIIRecord{
		Nom: "Meier", Prenom: "Hans", Email: "hans@bluewin.ch", Phone: "0791234567",
		DOB: "1985-03-12", Address: "8001 Zürich", IBAN: "CH9300762011623852957",
	})
	for _, want := range []string{
		"nom: Meier", "prenom: Hans", "date_naissance: 1985-03-12",
		"adresse: 8001 Zürich", "email: hans@bluewin.ch", "telephone: 0791234567",
		"iban: CH9300762011623852957",
	} {
		if !stringsContains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestFormatPIIRecord_NoIBAN(t *testing.T) {
	s := FormatPIIRecord(PIIRecord{Nom: "Dupont", Email: "x@sunrise.ch", Phone: "0791112233"})
	if stringsContains(s, "iban:") {
		t.Error("iban line should be omitted when empty")
	}
}

func TestSwissPhone(t *testing.T) {
	for _, p := range []string{"0791234567", "+41 79 123 45 67", "044 123 45 67"} {
		if !isValidPhone(p) {
			t.Errorf("expected valid CH phone %q", p)
		}
	}
	if isValidPhone("0612345678") || isValidPhone("+33612345678") {
		t.Error("FR phones should be rejected")
	}
}

func TestSwissIBAN(t *testing.T) {
	if !isValidIBAN("CH9300762011623852957") {
		t.Fatal("CH IBAN rejected")
	}
	if isValidIBAN("FR7630006000011234567890189") {
		t.Fatal("FR IBAN should be rejected")
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
