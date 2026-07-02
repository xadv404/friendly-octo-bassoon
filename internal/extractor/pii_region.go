package extractor

import "regexp"

// Region géographique pour les regex PII (défaut: Suisse).
type Region string

const RegionCH Region = "ch"

var activeRegion = RegionCH

// SetRegion change le profil PII (seul "ch" supporté pour l'instant).
func SetRegion(r Region) {
	if r == "" {
		r = RegionCH
	}
	activeRegion = r
	initPIIRegex()
}

type regionProfile struct {
	phone   *regexp.Regexp
	iban    *regexp.Regexp
	address *regexp.Regexp
}

var profileCH = regionProfile{
	// Mobile 07x / fixe 0xx / +41 — formats suisses
	phone: regexp.MustCompile(
		`(?:(?:\+|00)41[\s.\-]?|0)\s?(?:7[5-9]|[2-9]\d)[\s.\-]?\d{3}[\s.\-]?\d{2}[\s.\-]?\d{2}`,
	),
	// IBAN suisse : CH + 2 chiffres + 17 alphanum (21 car.)
	iban: regexp.MustCompile(`\bCH[0-9]{2}[A-Z0-9]{17}\b`),
	// NPA 4 chiffres + localité (ex: 8001 Zürich)
	address: regexp.MustCompile(`\b[1-9]\d{3}\s+[\p{L}][\p{L}\s\-']{2,}`),
}

var (
	rePIIPhone *regexp.Regexp
	rePIIIBAN  *regexp.Regexp
	rePIIAddr  *regexp.Regexp
)

func initPIIRegex() {
	switch activeRegion {
	default:
		rePIIPhone = profileCH.phone
		rePIIIBAN = profileCH.iban
		rePIIAddr = profileCH.address
	}
}

func init() {
	initPIIRegex()
}
