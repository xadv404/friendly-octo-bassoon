package i18n

import (
	"github.com/sqli-hunter/sqli-hunter/internal/i18n/alert"
	"github.com/sqli-hunter/sqli-hunter/internal/i18n/bot"
)

// Bundle regroupe les textes bot (export) et alert (alertes scan).
type Bundle struct {
	Locale Locale
	Bot    bot.Texts
	Alert  alert.Texts
}

// Load charge le bundle pour la locale courante.
func Load() *Bundle {
	return ForLocale(FromEnv())
}

// ForLocale retourne le bundle pour une locale donnée.
func ForLocale(loc Locale) *Bundle {
	if loc != EN {
		loc = FR
	}
	return &Bundle{
		Locale: loc,
		Bot:    bot.For(string(loc)),
		Alert:  alert.For(string(loc)),
	}
}
