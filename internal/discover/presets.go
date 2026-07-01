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
			"devis", "sinistre", "contrat", "police", "claim", "policy", "quote",
			"mutuelle", "assurance", "insurance", "souscription", "adherent",
			"espace-client", "espaceclient", "courtier", "broker", "sinistres",
			"remboursement", "prevoyance", "habitation", "auto",
		},
		Params: []string{
			"id", "ref", "num", "policy", "policy_id", "policyid", "claim_id",
			"claimid", "contract_id", "contractid", "numero_police", "num_police",
			"devis", "quote_id", "dossier", "client_id", "member_id", "insured",
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
