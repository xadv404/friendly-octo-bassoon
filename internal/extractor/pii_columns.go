package extractor

import (
	"fmt"
	"regexp"
	"strings"
)

// Colonnes adresse éclatées (plz + ort + rue) fusionnées pour le dump SQL.
const (
	PIIStreet PIIColumnKind = "street"
	PIIPLZ    PIIColumnKind = "plz"
	PIIOrt    PIIColumnKind = "ort"
)

var streetColumnPattern = regexp.MustCompile(`(?i)(?:^|_)(?:strasse|strasse_nr|rue|street|addr1|address_line)(?:$|_)`)
var plzColumnPattern = regexp.MustCompile(`(?i)(?:^|_)(?:plz|npa|zip|postal_code|code_postal|postcode)(?:$|_)`)
var ortColumnPattern = regexp.MustCompile(`(?i)(?:^|_)(?:ort|ville|city|gemeinde|localite|localité)(?:$|_)`)

// classifyColumnExtended classifie aussi plz/ort/rue séparément.
func classifyColumnExtended(name string) (PIIColumnKind, bool) {
	name = strings.TrimSpace(name)
	if streetColumnPattern.MatchString(name) {
		return PIIStreet, true
	}
	if plzColumnPattern.MatchString(name) {
		return PIIPLZ, true
	}
	if ortColumnPattern.MatchString(name) {
		return PIIOrt, true
	}
	return ClassifyColumn(name)
}

// SelectPIIColumnsExtended retourne toutes les colonnes PII y compris plz/ort/rue.
func SelectPIIColumnsExtended(columns []string) map[PIIColumnKind]string {
	out := make(map[PIIColumnKind]string)
	for _, col := range columns {
		col = strings.TrimSpace(col)
		if col == "" {
			continue
		}
		kind, ok := classifyColumnExtended(col)
		if !ok {
			continue
		}
		if _, exists := out[kind]; !exists {
			out[kind] = col
		}
	}
	return out
}

// addressColumnsMet vérifie qu'on peut reconstituer une adresse depuis le schéma.
func addressColumnsMet(cols map[PIIColumnKind]string) bool {
	if c, ok := cols[PIIAddress]; ok && c != "" {
		return true
	}
	if cols[PIIPLZ] != "" && cols[PIIOrt] != "" {
		return true
	}
	if cols[PIIStreet] != "" && (cols[PIIPLZ] != "" || cols[PIIOrt] != "") {
		return true
	}
	if cols[PIIStreet] != "" {
		return true // rue + numéro en base
	}
	return false
}

// HasMinimumPIIColumns vérifie que la table expose une colonne email.
func HasMinimumPIIColumns(cols map[PIIColumnKind]string) bool {
	return cols[PIIEmail] != ""
}

// addressSQLExpr construit l'expression SQL pour le champ adresse (fusion plz/ort/rue).
func addressSQLExpr(dbms string, cols map[PIIColumnKind]string) string {
	if c, ok := cols[PIIAddress]; ok && c != "" {
		return quoteIdent(dbms, c)
	}
	var parts []string
	if c := cols[PIIStreet]; c != "" {
		parts = append(parts, quoteIdent(dbms, c))
	}
	if c := cols[PIIPLZ]; c != "" {
		parts = append(parts, quoteIdent(dbms, c))
	}
	if c := cols[PIIOrt]; c != "" {
		parts = append(parts, quoteIdent(dbms, c))
	}
	if len(parts) == 0 {
		return "''"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	return fmt.Sprintf(`CONCAT_WS(' ', %s)`, strings.Join(parts, ", "))
}
