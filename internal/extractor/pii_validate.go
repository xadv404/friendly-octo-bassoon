package extractor

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var (
	reEmailStrict = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9._%+\-]*[a-z0-9])?@[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?)+$`)
	reStreetCH    = regexp.MustCompile(`(?i)(?:strasse|str\.|weg|platz|gasse|rue|chemin|avenue|av\.|route|via|allee|allée)`)
)

// Préfixes mobiles suisses (07x).
var swissMobilePrefixes = []string{"075", "076", "077", "078", "079"}

// Indicatifs régionaux suisses (0xx).
var swissLandlinePrefixes = []string{
	"21", "22", "23", "24", "25", "26", "27",
	"31", "32", "33", "34",
	"41", "42", "43", "44",
	"51", "52", "53", "54", "55", "56", "57", "58", "59",
	"61", "62",
	"71", "72", "73", "74", "81", "91",
}

var emailDomainBlocklist = []string{
	"example.com", "example.org", "example.net", "test.com", "test.ch",
	"localhost", "invalid", "email.com", "domain.com",
}

var emailLocalBlocklist = []string{
	"noreply", "no-reply", "mailer-daemon", "postmaster", "webmaster",
	"donotreply", "do-not-reply",
	"select", "union", "error", "null", "syntax",
}

var nameBlocklist = map[string]bool{
	"null": true, "select": true, "union": true, "admin": true, "user": true,
	"users": true, "test": true, "error": true, "syntax": true, "mysql": true,
	"mariadb": true, "xpath": true, "total": true, "results": true, "items": true,
	"have": true, "from": true, "where": true, "table": true, "tables": true,
	"column": true, "columns": true, "varchar": true, "int": true, "name": true,
	"type": true, "value": true, "values": true, "data": true, "string": true,
	"group": true, "concat": true, "version": true, "database": true,
	"true": true, "false": true, "none": true, "unknown": true, "root": true,
	"localhost": true, "html": true, "body": true, "http": true, "https": true,
	"result": true, "search": true, "product": true, "account": true, "order": true,
	"orders": true, "invoice": true, "page": true, "index": true, "default": true,
	"extractvalue": true, "updatexml": true, "information": true, "schema": true,
	"confirmed": true, "high": true, "medium": true, "low": true,
}

// extractEmail trouve et valide un email dans une chaîne.
func extractEmail(s string) string {
	s = strings.TrimSpace(s)
	if isValidEmail(s) {
		return strings.ToLower(s)
	}
	// Chercher un token email dans du texte plus large
	candidates := rePIIEmail.FindAllString(s, -1)
	for _, c := range candidates {
		if isValidEmail(c) {
			return strings.ToLower(c)
		}
	}
	return ""
}

// extractPhone trouve et valide un téléphone CH dans une chaîne.
func extractPhone(s string) string {
	s = strings.TrimSpace(s)
	if isValidPhone(s) && !isPhoneInVersionContext(s, s) {
		return normalizePhone(s)
	}
	if rePIIPhone != nil {
		candidates := rePIIPhone.FindAllString(s, -1)
		for _, c := range candidates {
			if isValidPhone(c) && !isPhoneInVersionContext(s, c) {
				return normalizePhone(c)
			}
		}
	}
	return ""
}

// extractIBAN trouve et valide un IBAN CH (checksum mod-97).
func extractIBAN(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if isValidIBAN(s) {
		return s
	}
	if rePIIIBAN != nil {
		for _, c := range rePIIIBAN.FindAllString(s, -1) {
			if isValidIBAN(c) {
				return c
			}
		}
	}
	return ""
}

func isValidEmail(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) < 6 || len(s) > 100 {
		return false
	}
	if strings.Count(s, "@") != 1 {
		return false
	}
	if !reEmailStrict.MatchString(s) {
		return false
	}
	parts := strings.Split(s, "@")
	local, domain := parts[0], parts[1]
	if len(local) < 1 || len(domain) < 4 {
		return false
	}
	dot := strings.LastIndex(domain, ".")
	if dot < 1 || len(domain[dot+1:]) < 2 {
		return false
	}
	for _, b := range emailLocalBlocklist {
		if local == b || strings.HasPrefix(local, b+"+") {
			return false
		}
	}
	for _, b := range emailDomainBlocklist {
		if domain == b || strings.HasSuffix(domain, "."+b) {
			return false
		}
	}
	return true
}

func isValidPhone(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || rePIIPhone == nil || !rePIIPhone.MatchString(s) {
		return false
	}
	n := normalizePhone(s)
	if strings.HasPrefix(n, "+33") || strings.HasPrefix(n, "0033") {
		return false
	}
	return isValidSwissNationalNumber(n)
}

func isValidSwissNationalNumber(n string) bool {
	var national string
	switch {
	case strings.HasPrefix(n, "+41"):
		national = "0" + n[3:]
	case strings.HasPrefix(n, "0041"):
		national = "0" + n[4:]
	case strings.HasPrefix(n, "0"):
		national = n
	default:
		return false
	}
	if len(national) != 10 || !isAllDigits(national) {
		return false
	}
	if national == "0999999999" || national == "0000000000" {
		return false
	}
	prefix3 := national[:3]
	prefix2 := national[1:3]
	for _, m := range swissMobilePrefixes {
		if prefix3 == m {
			return true
		}
	}
	for _, l := range swissLandlinePrefixes {
		if prefix2 == l {
			return true
		}
	}
	return false
}

func isValidIBAN(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if len(s) != 21 || !strings.HasPrefix(s, "CH") {
		return false
	}
	if rePIIIBAN == nil || !rePIIIBAN.MatchString(s) {
		return false
	}
	for _, c := range s[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}
	return ibanMod97(s) == 1
}

func ibanMod97(iban string) int {
	rearranged := iban[4:] + iban[:4]
	rem := 0
	for _, c := range rearranged {
		var chunk string
		if c >= '0' && c <= '9' {
			chunk = string(c)
		} else if c >= 'A' && c <= 'Z' {
			chunk = strconv.Itoa(int(c - 'A' + 10))
		} else {
			return -1
		}
		for _, d := range chunk {
			rem = (rem*10 + int(d-'0')) % 97
		}
	}
	return rem
}

func isValidDOB(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !rePIIDOB.MatchString(s) {
		return false
	}
	t, ok := parseDOB(s)
	if !ok {
		return false
	}
	now := time.Now()
	if t.Year() < 1900 || t.After(now) {
		return false
	}
	// Âge max 120 ans
	if t.Before(now.AddDate(-120, 0, 0)) {
		return false
	}
	return true
}

func parseDOB(s string) (time.Time, bool) {
	formats := []string{
		"2006-01-02", "2006/01/02", "2006.01.02",
		"02-01-2006", "02/01/2006", "02.01.2006",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func isValidName(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 2 || len(s) > 50 {
		return false
	}
	if !rePIIName.MatchString(s) {
		return false
	}
	lower := strings.ToLower(s)
	if nameBlocklist[lower] {
		return false
	}
	if isPIINoise(lower) {
		return false
	}
	// Pas que des chiffres / pas de caractères SQL
	for _, r := range s {
		if r == '<' || r == '>' || r == '=' || r == ';' || r == '{' || r == '}' {
			return false
		}
	}
	// Au moins 2 lettres
	letters := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
		}
	}
	return letters >= 2
}

func isValidAddress(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) < 8 || len(s) > 200 {
		return false
	}
	if isSQLNoise(s) || isPIINoise(s) {
		return false
	}
	if rePIIAddr != nil && rePIIAddr.MatchString(s) {
		return true
	}
	if reStreetCH.MatchString(s) && regexp.MustCompile(`\d`).MatchString(s) {
		return true
	}
	// Rue française/internationale : "12 rue de Paris"
	if regexp.MustCompile(`(?i)^\d{1,4}\s+(?:rue|chemin|avenue|route|via)\b`).MatchString(s) {
		return true
	}
	return false
}

func isPhoneInVersionContext(src, match string) bool {
	idx := strings.Index(src, match)
	if idx < 0 {
		return false
	}
	start := idx
	for start > 0 && (src[start-1] == '.' || src[start-1] == '-' || unicode.IsDigit(rune(src[start-1]))) {
		start--
	}
	end := idx + len(match)
	for end < len(src) && (src[end] == '.' || src[end] == '-' || unicode.IsDigit(rune(src[end]))) {
		end++
	}
	segment := src[start:end]
	return regexp.MustCompile(`\d+\.\d+\.\d+`).MatchString(segment)
}

func isPIINoise(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if nameBlocklist[lower] {
		return true
	}
	noise := []string{
		"undefined", "nan", "nil", "syntax", "error", "warning",
		"javascript", "function", "object", "array", "json",
		"password", "token", "session", "cookie", "bearer",
	}
	for _, n := range noise {
		if lower == n {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// sanitizeRecord nettoie et ne garde que l'email pour l'export.
func sanitizeRecord(r *PIIRecord) {
	em := extractEmail(r.Email)
	if em == "" && r.Raw != "" {
		em = extractEmail(r.Raw)
	}
	r.Email = em
	r.Nom, r.Prenom, r.Phone, r.DOB, r.Address, r.IBAN = "", "", "", "", "", ""
}
