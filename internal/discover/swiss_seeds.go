package discover

import "strings"

// SwissSeedDomains liste de domaines .ch variés pour la découverte large (mode ch).
// Wayback n'autorise pas *.ch/* — on interroge chaque domaine séparément.
func SwissSeedDomains() []string {
	raw := []string{
		"swisscom.ch", "sunrise.ch", "salt.ch", "bluewin.ch", "srf.ch", "rts.ch",
		"migros.ch", "coop.ch", "manor.ch", "digitec.ch", "galaxus.ch", "ricardo.ch", "tutti.ch",
		"postfinance.ch", "ubs.ch", "zkb.ch", "raiffeisen.ch", "post.ch",
		"sbb.ch", "tl.ch", "bls.ch",
		"helsana.ch", "css.ch", "swica.ch", "sanitas.ch", "concordia.ch", "groupemutuel.ch",
		"admin.ch", "ethz.ch", "epfl.ch", "unibe.ch", "unige.ch", "unil.ch",
		"swisspass.ch", "search.ch", "local.ch", "jobup.ch", "jobs.ch",
		"tcs.ch", "comparis.ch", "homegate.ch", "immoscout24.ch", "anibis.ch",
		"autoscout24.ch", "swissinfo.ch", "amazon.ch", "ikea.ch", "mediamarkt.ch",
		"axa.ch", "mobiliar.ch", "generali.ch", "baloise.ch",
		"romande-energie.ch", "groupe-e.ch", "ewz.ch", "vaudoise.ch", "zurich.ch",
		"ticketcorner.ch", "switch.ch", "nic.ch", "bit.ch", "hostpoint.ch",
		"infomaniak.ch",
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, len(raw))
	for _, d := range raw {
		d = NormalizeSwissDomain(d)
		if !strings.HasSuffix(d, ".ch") {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}
