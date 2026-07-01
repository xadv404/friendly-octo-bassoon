package discover

// Preset regroupe des filtres prêts à l'emploi.
type Preset struct {
	Name   string
	Paths  []string
	Params []string
}

// Presets disponibles via --preset.
var Presets = map[string]Preset{
	"insurance": {
		Name: "insurance",
		Paths: []string{
			// FR
			"devis", "sinistre", "contrat", "police", "assurance", "mutuelle",
			// CH — DE/FR/IT
			"versicherung", "offerte", "schaden", "schadenfall", "police", "praemie",
			"krankenkasse", "kvg", "lamal", "krankenversicherung", "unfallversicherung",
			"assicurazione", "preventivo", "sinistro", "premio",
			"espace-client", "kundenportal", "myaxa", "css", "helsana", "swica", "groupemutuel",
			"remboursement", "remboursements", "adherent", "versicherte",
		},
		Params: []string{
			"id", "ref", "num", "policy", "policy_id", "policen_nr", "policennummer",
			"claim_id", "schaden_id", "contract_id", "vertrag_id", "offerte_id",
			"client_id", "kunden_id", "member_id", "versicherten_nr", "insured",
		},
	},
	"sqli": {
		Name: "sqli",
		Paths: []string{
			"product", "detail", "view", "page", "article", "news", "item",
			"search", "category", "shop", "catalog", "admin", "api", "user",
		},
		Params: []string{
			"id", "pid", "cat", "catid", "page", "uid", "user_id", "q", "query",
			"ref", "nid", "itemid", "productid",
		},
	},
}

// PresetNames retourne les noms de presets triés.
func PresetNames() []string {
	names := make([]string, 0, len(Presets))
	for k := range Presets {
		names = append(names, k)
	}
	return names
}
