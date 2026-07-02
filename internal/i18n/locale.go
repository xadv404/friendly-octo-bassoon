package i18n

import (
	"os"
	"strings"
)

// Locale code langue (fr, en).
type Locale string

const (
	FR Locale = "fr"
	EN Locale = "en"
)

// DefaultLocale langue par défaut.
const DefaultLocale = FR

// FromEnv lit TELEGRAM_LOCALE ou APP_LOCALE (défaut: fr).
func FromEnv() Locale {
	for _, key := range []string{"TELEGRAM_LOCALE", "APP_LOCALE"} {
		if v := strings.ToLower(strings.TrimSpace(os.Getenv(key))); v != "" {
			if loc := parseLocale(v); loc != "" {
				return loc
			}
		}
	}
	return DefaultLocale
}

func parseLocale(raw string) Locale {
	switch raw {
	case "fr", "fra", "french", "français", "francais":
		return FR
	case "en", "eng", "english":
		return EN
	default:
		return ""
	}
}
