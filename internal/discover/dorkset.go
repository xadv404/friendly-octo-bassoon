package discover

// DorkSet sélectionne le jeu de dorks pour la découverte.
type DorkSet int

const (
	DorkSetVuln DorkSet = iota
	DorkSetBig
	DorkSetTop
)

// BuildDorks retourne les dorks selon le profil demandé.
func BuildDorks(set DorkSet, domain string, subs bool) []string {
	switch set {
	case DorkSetBig:
		return BuildBigDorks(domain, subs)
	case DorkSetTop:
		return BuildTopDorks(domain, subs)
	default:
		return BuildVulnDorks(domain, subs)
	}
}

// OrderedDorks applique la rotation (seed) au jeu de dorks.
func OrderedDorks(set DorkSet, domain string, subs bool, seed int) []string {
	return DailyDorkOrder(BuildDorks(set, domain, subs), seed)
}
