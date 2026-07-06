package results

import "strings"

// Fournisseurs email grand public uniquement (webmail / ISP).
// Les domaines d'organisation (phzh.ch, eda.admin.ch, etc.) sont rejetés.
var knownEmailProviders = map[string]struct{}{
	// Google
	"gmail.com": {}, "googlemail.com": {},
	// Microsoft
	"hotmail.com": {}, "hotmail.ch": {}, "hotmail.fr": {}, "hotmail.de": {}, "hotmail.co.uk": {},
	"outlook.com": {}, "outlook.ch": {}, "outlook.fr": {}, "outlook.de": {},
	"live.com": {}, "live.ch": {}, "live.fr": {}, "live.de": {},
	"msn.com": {}, "windowslive.com": {},
	// Apple
	"icloud.com": {}, "me.com": {}, "mac.com": {},
	// Yahoo
	"yahoo.com": {}, "yahoo.ch": {}, "yahoo.fr": {}, "yahoo.de": {}, "yahoo.co.uk": {},
	"ymail.com": {}, "rocketmail.com": {},
	// Swiss ISP / telecom
	"bluewin.ch": {}, "sunrise.ch": {}, "hispeed.ch": {}, "swissonline.ch": {},
	"vtx.ch": {}, "quickline.ch": {}, "cablecom.ch": {}, "init7.net": {},
	// GMX / United Internet
	"gmx.ch": {}, "gmx.com": {}, "gmx.net": {}, "gmx.de": {}, "gmx.at": {}, "gmx.co.uk": {},
	"web.de": {}, "mail.com": {},
	// Proton
	"protonmail.com": {}, "proton.me": {}, "pm.me": {}, "protonmail.ch": {},
	// AOL
	"aol.com": {}, "aol.ch": {},
	// France (frontalier)
	"orange.fr": {}, "wanadoo.fr": {}, "free.fr": {}, "laposte.net": {},
	"sfr.fr": {}, "neuf.fr": {}, "bbox.fr": {},
	// Allemagne / Autriche
	"t-online.de": {}, "arcor.de": {}, "freenet.de": {},
	// Italie
	"libero.it": {}, "alice.it": {}, "tin.it": {}, "virgilio.it": {},
	// Belgique / Luxembourg
	"skynet.be": {}, "telenet.be": {}, "pt.lu": {},
}

// IsKnownProvider indique si le domaine email est un fournisseur grand public connu.
func IsKnownProvider(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.Trim(domain, ".")
	if domain == "" {
		return false
	}
	_, ok := knownEmailProviders[domain]
	return ok
}

// IsKnownEmail valide format + fournisseur connu.
func IsKnownEmail(email string) bool {
	provider := EmailProvider(email)
	return provider != "" && IsKnownProvider(provider)
}
