package extractor

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// PIIColumnKind type de donnée personnelle.
type PIIColumnKind string

const (
	PIINom      PIIColumnKind = "nom"
	PIIPrenom   PIIColumnKind = "prenom"
	PIIEmail    PIIColumnKind = "email"
	PIIPhone    PIIColumnKind = "phone"
	PIIDOB      PIIColumnKind = "dob"
	PIIAddress  PIIColumnKind = "address"
	PIIIBAN     PIIColumnKind = "iban"
)

// PIIRecord enregistrement utilisateur extrait.
type PIIRecord struct {
	Nom      string
	Prenom   string
	Email    string
	Phone    string
	DOB      string
	Address  string
	IBAN     string
	Table    string
	Raw      string
}

// ToModel convertit en structure exportable JSON/SQL.
func (r PIIRecord) ToModel() models.PIIUser {
	return models.PIIUser{
		Nom:           r.Nom,
		Prenom:        r.Prenom,
		DateNaissance: r.DOB,
		Adresse:       r.Address,
		Email:         r.Email,
		Telephone:     r.Phone,
		IBAN:          r.IBAN,
		Table:         r.Table,
	}
}

// FormatPIIRecord sérialise un enregistrement (une ligne, champs fixes).
func FormatPIIRecord(r PIIRecord) string {
	return FormatPIIBlock(r)
}

// FormatPIIBlock affiche un utilisateur au format lisible (CLI / SQL).
func FormatPIIBlock(r PIIRecord) string {
	u := r.ToModel()
	var b strings.Builder
	writePIIField(&b, "nom", u.Nom)
	writePIIField(&b, "prenom", u.Prenom)
	writePIIField(&b, "date_naissance", u.DateNaissance)
	writePIIField(&b, "adresse", u.Adresse)
	writePIIField(&b, "email", u.Email)
	writePIIField(&b, "telephone", u.Telephone)
	if u.IBAN != "" {
		writePIIField(&b, "iban", u.IBAN)
	}
	return strings.TrimRight(b.String(), "\n")
}

func writePIIField(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	fmt.Fprintf(b, "%s: %s\n", key, val)
}

var (
	rePIIEmail = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	rePIIDOB   = regexp.MustCompile(`\b(?:\d{4}[-./]\d{2}[-./]\d{2}|\d{2}[-./]\d{2}[-./]\d{4})\b`)
	rePIIName  = regexp.MustCompile(`^[\p{L}][\p{L}'\-\s]{1,48}[\p{L}]$`)
)

// rePIIPhone, rePIIIBAN, rePIIAddr — initialisés dans pii_region.go (profil CH).

var columnPatterns = map[PIIColumnKind]*regexp.Regexp{
	PIINom: regexp.MustCompile(`(?i)(?:^|_)(?:nom|nachname|lastname|last_name|surname|family_name|name)(?:$|_)`),
	PIIPrenom: regexp.MustCompile(`(?i)(?:^|_)(?:prenom|vorname|firstname|first_name|given_name)(?:$|_)`),
	PIIEmail: regexp.MustCompile(`(?i)(?:^|_)(?:email|e_mail|mail|courriel|email_address)(?:$|_)`),
	PIIPhone: regexp.MustCompile(`(?i)(?:^|_)(?:tel|telefon|telephone|phone|mobile|gsm|handy|numero|num_tel|phone_number|natel)(?:$|_)`),
	PIIDOB: regexp.MustCompile(`(?i)(?:^|_)(?:date_naissance|geburtsdatum|birthdate|birth_date|dob|naissance|date_of_birth)(?:$|_)`),
	PIIAddress: regexp.MustCompile(`(?i)(?:^|_)(?:adresse|address|addr|strasse|rue|street|ort|ville|city|plz|npa|zip|postal_code|code_postal|gemeinde)(?:$|_)`),
	PIIIBAN: regexp.MustCompile(`(?i)(?:^|_)(?:iban|konto|bank_account|compte_bancaire|kontonummer)(?:$|_)`),
}

var userTablePattern = regexp.MustCompile(`(?i)(?:^|_)(?:users?|kunden?|clients?|customers?|adherents?|versicherte?|members?|membres?|assures?|insured|subscribers?|policy_holders?|beneficiaires?|patients?|contacts?|accounts?|comptes?|personen?)(?:$|_)`)

// ClassifyColumn associe un nom de colonne SQL à un type PII.
func ClassifyColumn(name string) (PIIColumnKind, bool) {
	name = strings.TrimSpace(name)
	for kind, re := range columnPatterns {
		if re.MatchString(name) {
			return kind, true
		}
	}
	return "", false
}

// IsUserTable indique si le nom de table ressemble à des données utilisateurs.
func IsUserTable(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	return userTablePattern.MatchString(name)
}

// SelectPIIColumns retourne colonne SQL → type PII pour une table.
func SelectPIIColumns(columns []string) map[PIIColumnKind]string {
	out := make(map[PIIColumnKind]string)
	for _, col := range columns {
		col = strings.TrimSpace(col)
		if col == "" {
			continue
		}
		kind, ok := ClassifyColumn(col)
		if !ok {
			continue
		}
		if _, exists := out[kind]; !exists {
			out[kind] = col
		}
	}
	return out
}

// HasMinimumPIIColumns vérifie qu'une table a au moins email ou téléphone.
func HasMinimumPIIColumns(cols map[PIIColumnKind]string) bool {
	_, hasEmail := cols[PIIEmail]
	_, hasPhone := cols[PIIPhone]
	return hasEmail || hasPhone
}

// RecordMeetsMinimum valide un enregistrement : email ou téléphone obligatoire.
func RecordMeetsMinimum(r PIIRecord) bool {
	return isValidEmail(r.Email) || isValidPhone(r.Phone)
}

func isValidEmail(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return rePIIEmail.MatchString(s) && !strings.Contains(s, "example.com") && len(s) < 120
}

func isValidPhone(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if !rePIIPhone.MatchString(s) {
		return false
	}
	n := normalizePhone(s)
	// Rejeter numéros français
	if strings.HasPrefix(n, "+33") || strings.HasPrefix(n, "0033") {
		return false
	}
	if strings.HasPrefix(n, "06") && len(n) == 10 {
		return false
	}
	// Suisse : +41… ou 0 + 9 chiffres
	if strings.HasPrefix(n, "+41") {
		return len(n) >= 11 && len(n) <= 12
	}
	if strings.HasPrefix(n, "0") {
		return len(n) == 10
	}
	return false
}

func isValidIBAN(s string) bool {
	s = strings.TrimSpace(strings.ToUpper(strings.ReplaceAll(s, " ", "")))
	return s != "" && rePIIIBAN.MatchString(s)
}

func isValidAddress(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 5 || isSQLNoise(s) {
		return false
	}
	// Suisse : NPA 4 chiffres OU adresse libre ≥ 8 car.
	if rePIIAddr != nil && rePIIAddr.MatchString(s) {
		return true
	}
	return len(s) >= 8
}

func isValidDOB(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && rePIIDOB.MatchString(s)
}

func isValidName(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return false
	}
	return rePIIName.MatchString(s)
}

// ParseLabeledPII parse "nom=X|email=Y|tel=Z" depuis une réponse SQL.
func ParseLabeledPII(raw, table string) []PIIRecord {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var records []PIIRecord
	chunks := strings.Split(raw, ";;")
	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		r := PIIRecord{Table: table, Raw: chunk}
		for _, part := range strings.Split(chunk, "|") {
			part = strings.TrimSpace(part)
			idx := strings.Index(part, "=")
			if idx <= 0 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(part[:idx]))
			val := strings.TrimSpace(part[idx+1:])
			if val == "" {
				continue
			}
			switch key {
			case "nom", "lastname", "last_name", "nachname", "name":
				if isValidName(val) {
					r.Nom = val
				}
			case "prenom", "firstname", "first_name", "vorname":
				if isValidName(val) {
					r.Prenom = val
				}
			case "email", "mail":
				if em := rePIIEmail.FindString(val); em != "" {
					r.Email = em
				}
			case "tel", "phone", "telephone", "mobile", "telefon", "natel", "handy":
				if ph := rePIIPhone.FindString(val); ph != "" {
					r.Phone = normalizePhone(ph)
				}
			case "naissance", "dob", "birthdate", "geburtsdatum":
				if d := rePIIDOB.FindString(val); d != "" {
					r.DOB = d
				}
			case "adresse", "address", "addr", "strasse", "ort":
				if isValidAddress(val) {
					r.Address = val
				}
			case "iban", "konto":
				if ib := rePIIIBAN.FindString(strings.ToUpper(strings.ReplaceAll(val, " ", ""))); ib != "" {
					r.IBAN = ib
				}
			}
		}
		if RecordMeetsMinimum(r) {
			records = append(records, r)
		}
	}
	return records
}

// ScanPIIInText extrait des PII depuis du texte/JSON libre (NoSQL, fuites).
func ScanPIIInText(body string) []PIIRecord {
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}

	r := PIIRecord{Raw: truncate(body, 300)}
	if em := rePIIEmail.FindString(body); em != "" {
		r.Email = em
	}
	if ph := rePIIPhone.FindString(body); ph != "" {
		r.Phone = normalizePhone(ph)
	}
	if ib := rePIIIBAN.FindString(strings.ToUpper(strings.ReplaceAll(body, " ", ""))); ib != "" {
		r.IBAN = ib
	}
	if d := rePIIDOB.FindString(body); d != "" {
		r.DOB = d
	}

	// Noms depuis JSON courant
	for _, key := range []string{`"nom"`, `"nachname"`, `"prenom"`, `"vorname"`, `"firstname"`, `"lastname"`, `"first_name"`, `"last_name"`} {
		if v := jsonStringValue(body, key); v != "" && isValidName(v) {
			if strings.Contains(strings.ToLower(key), "pre") || strings.Contains(key, "first") {
				r.Prenom = v
			} else {
				r.Nom = v
			}
		}
	}
	for _, key := range []string{`"adresse"`, `"address"`, `"strasse"`, `"ort"`} {
		if v := jsonStringValue(body, key); v != "" && isValidAddress(v) {
			r.Address = v
		}
	}

	if !RecordMeetsMinimum(r) {
		return nil
	}
	return []PIIRecord{r}
}

func jsonStringValue(body, key string) string {
	idx := strings.Index(strings.ToLower(body), strings.ToLower(key))
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(key):]
	colon := strings.Index(rest, ":")
	if colon < 0 {
		return ""
	}
	rest = strings.TrimSpace(rest[colon+1:])
	if len(rest) == 0 {
		return ""
	}
	if rest[0] == '"' {
		end := strings.Index(rest[1:], `"`)
		if end < 0 {
			return ""
		}
		return rest[1 : end+1]
	}
	return ""
}

func normalizePhone(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) || r == '+' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isSQLNoise(s string) bool {
	lower := strings.ToLower(s)
	noise := []string{"select", "union", "null", "syntax", "error", "xpath", "group_concat"}
	for _, n := range noise {
		if strings.Contains(lower, n) {
			return true
		}
	}
	return false
}

func splitTableList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" && IsUserTable(part) {
			out = append(out, part)
		}
	}
	return out
}

func splitColumnList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
