package extractor

import "testing"

// goldenPositive — enregistrements CH valides qui DOIVENT passer (0 FN).
var goldenPositive = []struct {
	name string
	raw  string
}{
	{
		name: "standard labeled",
		raw:  "nom=Meier|prenom=Hans|email=hans.meier@bluewin.ch|tel=0791234567|naissance=1985-03-12|adresse=Bahnhofstrasse 1, 8001 Zürich",
	},
	{
		name: "dob swiss dot format",
		raw:  "nom=Dupont|prenom=Marie|email=marie@sunrise.ch|tel=0441234567|naissance=15.05.1990|adresse=Rue du Rhône 12, 1204 Genève",
	},
	{
		name: "short names",
		raw:  "nom=Li|prenom=Ng|email=li.ng@canton-ge.ch|tel=0761234567|naissance=01.01.2000|adresse=Chemin des Vignes 3, 1004 Lausanne",
	},
	{
		name: "split address columns",
		raw:  "nom=Schmid|prenom=Anna|email=anna@hispeed.ch|tel=0311234567|naissance=1992-11-08|strasse=Bahnhofstrasse 5|plz=3000|ort=Bern",
	},
	{
		name: "basel landline 061",
		raw:  "nom=Brunner|prenom=Peter|email=peter@css.ch|tel=0612345678|naissance=1978-06-22|adresse=Freie Strasse 10, 4001 Basel",
	},
	{
		name: "international format phone",
		raw:  "nom=Rossi|prenom=Marco|email=marco@ticino.ch|tel=+41 79 123 45 67|naissance=22/08/1988|adresse=Via Nassa 4, 6900 Lugano",
	},
	{
		name: "french street style",
		raw:  "nom=Martin|prenom=Claire|email=claire@romandie.ch|tel=0211234567|naissance=03.12.1975|adresse=12 rue de Paris, 1003 Lausanne",
	},
	{
		name: "npa city only",
		raw:  "nom=Keller|prenom=Sara|email=sara@swisscom.ch|tel=0781234567|naissance=1995-07-01|adresse=8001 Zürich",
	},
}

// goldenNegative — textes qui NE DOIVENT PAS produire d'enregistrement (0 FP).
var goldenNegative = []struct {
	name string
	body string
}{
	{"mysql xpath error", "XPATH syntax error: '~8.0.32-MySQL~'"},
	{"db stats", "total: 847 items in database"},
	{"auth error json", `{"error":"invalid credentials"}`},
	{"jwt token", `{"token":"eyJhbG","user":{"role":"admin"}}`},
	{"sql query", "SELECT * FROM users WHERE id=1"},
	{"partial email tel only", `email=hans@bluewin.ch|tel=0791234567`},
	{"partial nom email tel", `nom=Dupont|email=marie@sunrise.ch|tel=0791234567`},
	{"sql keyword email", `email=select@union.com|tel=12345`},
	{"admin noreply invalid tel", "nom=admin|email=noreply@css.ch|tel=0999999999"},
	{"sql names missing fields", "nom=Error|prenom=Syntax|email=hans@bluewin.ch|tel=0791234567"},
	{"french mobile +33", `{"nachname":"Dupont","vorname":"Jean","email":"jean@test.ch","telefon":"+33612345678","geburtsdatum":"1985-03-12","strasse":"Rue 1, 1204 Genève"}`},
	{"version string 802.11", "802.11 wireless standard revision"},
	{"wifi version context", "MySQL version 8.0.32-MySQL community"},
}

func TestGolden_PositiveZeroFN(t *testing.T) {
	for _, tc := range goldenPositive {
		t.Run(tc.name, func(t *testing.T) {
			recs := ParseLabeledPII(tc.raw, "kunden")
			if len(recs) != 1 {
				t.Fatalf("expected 1 record, got %d for %q", len(recs), tc.raw)
			}
			r := recs[0]
			if !RecordMeetsMinimum(r) {
				t.Fatalf("record should meet minimum: %+v", r)
			}
			if r.Nom == "" || r.Prenom == "" || r.DOB == "" || r.Address == "" || r.Email == "" || r.Phone == "" {
				t.Fatalf("incomplete fields: %+v", r)
			}
		})
	}
}

func TestGolden_NegativeZeroFP(t *testing.T) {
	for _, tc := range goldenNegative {
		t.Run(tc.name, func(t *testing.T) {
			if recs := ScanPIIInText(tc.body); len(recs) > 0 {
				t.Fatalf("ScanPIIInText false positive: %+v", recs[0])
			}
			if recs := ParseLabeledPII(tc.body, "users"); len(recs) > 0 {
				t.Fatalf("ParseLabeledPII false positive: %+v", recs[0])
			}
		})
	}
}

func TestGolden_NoSQLSplitAddress(t *testing.T) {
	body := `{"nachname":"Meier","vorname":"Hans","email":"user@bluewin.ch","telefon":"0791234567","geburtsdatum":"12.03.1985","strasse":"Bahnhofstrasse 1","plz":"8001","ort":"Zürich"}`
	recs := ScanPIIInText(body)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record from split JSON address, got %d", len(recs))
	}
	if recs[0].Address == "" {
		t.Fatal("address should be merged from strasse+plz+ort")
	}
}

func TestGolden_HasMinimumPIIColumns_Split(t *testing.T) {
	split := map[PIIColumnKind]string{
		PIINom: "nachname", PIIPrenom: "vorname", PIIDOB: "geburtsdatum",
		PIIPLZ: "plz", PIIOrt: "ort", PIIEmail: "email", PIIPhone: "telefon",
	}
	if !HasMinimumPIIColumns(split) {
		t.Fatal("plz+ort should satisfy address column requirement")
	}
	streetOnly := map[PIIColumnKind]string{
		PIINom: "nachname", PIIPrenom: "vorname", PIIDOB: "geburtsdatum",
		PIIStreet: "strasse", PIIEmail: "email", PIIPhone: "telefon",
	}
	if !HasMinimumPIIColumns(streetOnly) {
		t.Fatal("street column alone should satisfy address requirement")
	}
}

func TestGolden_Validators(t *testing.T) {
	// 0 FN — formats valides
	for _, n := range []string{"Li", "Ng", "Müller", "Dupont-Jones"} {
		if !isValidName(n) {
			t.Errorf("valid name rejected (FN): %s", n)
		}
	}
	for _, d := range []string{"1985-03-12", "15.05.1990", "01/01/2000", "22.08.1988"} {
		if !isValidDOB(d) {
			t.Errorf("valid dob rejected (FN): %s", d)
		}
	}
	for _, p := range []string{"0791234567", "0612345678", "044 123 45 67", "+41 79 123 45 67"} {
		if !isValidPhone(p) {
			t.Errorf("valid phone rejected (FN): %s", p)
		}
	}
	for _, a := range []string{
		"Bahnhofstrasse 1, 8001 Zürich",
		"8001 Zürich",
		"12 rue de Paris, 1003 Lausanne",
		"Route de la Session 5, 1200 Genève",
	} {
		if !isValidAddress(a) {
			t.Errorf("valid address rejected (FN): %q", a)
		}
	}

	// 0 FP — formats invalides
	for _, n := range []string{"null", "select", "admin", "x", "1234", "error"} {
		if isValidName(n) {
			t.Errorf("invalid name accepted (FP): %s", n)
		}
	}
	for _, p := range []string{"0999999999", "+33612345678", "12345", "8.0.32", "802.11"} {
		if isValidPhone(p) {
			t.Errorf("invalid phone accepted (FP): %s", p)
		}
	}
	for _, a := range []string{"error", "select union", "short", "zurich"} {
		if isValidAddress(a) {
			t.Errorf("invalid address accepted (FP): %q", a)
		}
	}
}
