package discover

// Preset regroupe des filtres prêts à l'emploi.
type Preset struct {
	Name   string
	Paths  []string
	Params []string
}

var sqliPaths = []string{
	"product", "detail", "view", "page", "article", "news", "item",
	"search", "category", "shop", "catalog", "admin", "api", "user",
}

var sqliParams = []string{
	"id", "pid", "cat", "catid", "page", "uid", "user_id", "q", "query",
	"ref", "nid", "itemid", "productid",
}

var insurancePaths = []string{
	"devis", "sinistre", "contrat", "police", "assurance", "mutuelle",
	"versicherung", "offerte", "schaden", "schadenfall", "praemie",
	"krankenkasse", "kvg", "lamal", "krankenversicherung", "unfallversicherung",
	"assicurazione", "preventivo", "sinistro", "premio",
	"espace-client", "kundenportal", "myaxa", "helsana", "swica", "groupemutuel",
	"remboursement", "remboursements", "adherent", "versicherte",
}

var insuranceParams = []string{
	"ref", "num", "policy", "policy_id", "policen_nr", "policennummer",
	"claim_id", "schaden_id", "contract_id", "vertrag_id", "offerte_id",
	"client_id", "kunden_id", "member_id", "versicherten_nr", "insured",
}

// Presets disponibles via --preset (optionnels — par défaut toutes les URLs avec ?param=).
var Presets = map[string]Preset{
	"bounty": {
		Name: "bounty",
		Paths: uniqueStrings(append(append([]string{}, sqliPaths...), append(insurancePaths,
			"portal", "client", "account", "profile", "order", "invoice",
			"payment", "booking", "patient", "member", "login", "register",
		)...)),
		Params: uniqueStrings(append(append([]string{}, sqliParams...), append(insuranceParams,
			"order_id", "invoice_id", "session",
		)...)),
	},
	"insurance": {
		Name:   "insurance",
		Paths:  insurancePaths,
		Params: uniqueStrings(append([]string{"id"}, insuranceParams...)),
	},
	"sqli": {
		Name:   "sqli",
		Paths:  sqliPaths,
		Params: sqliParams,
	},
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// PresetNames retourne les noms de presets triés.
func PresetNames() []string {
	names := make([]string, 0, len(Presets))
	for k := range Presets {
		names = append(names, k)
	}
	return names
}
