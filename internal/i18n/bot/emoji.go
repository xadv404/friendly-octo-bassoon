package bot

import "strings"

// ProviderEmoji retourne l'emoji associé à un fournisseur email.
func ProviderEmoji(provider string) string {
	base := strings.ToLower(provider)
	switch {
	case strings.Contains(base, "gmail"), strings.Contains(base, "googlemail"):
		return "📧"
	case strings.Contains(base, "bluewin"):
		return "📬"
	case strings.Contains(base, "gmx"):
		return "✉️"
	case strings.Contains(base, "yahoo"):
		return "💌"
	case strings.Contains(base, "icloud"), strings.Contains(base, "me.com"):
		return "☁️"
	case strings.Contains(base, "hotmail"), strings.Contains(base, "outlook"), strings.Contains(base, "live."):
		return "📨"
	case strings.Contains(base, "sunrise"), strings.Contains(base, "hispeed"):
		return "🇨🇭"
	default:
		return "📮"
	}
}
