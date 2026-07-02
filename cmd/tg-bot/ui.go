package main

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

const botName = "MAIL LIST"

func providerEmoji(provider string) string {
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

func welcomeCaption(cfg config) string {
	stock := stockMessage(cfg)
	return fmt.Sprintf("🇨🇭 *%s*\n_Stock emails .ch — extraction instantanée_\n\n%s", botName, stock)
}

func stockMessage(cfg config) string {
	list, err := results.ListProviders(cfg.resultsDir)
	if err != nil || len(list) == 0 {
		return "📭 *Stock vide*\n\nAucun email dispo pour le moment."
	}

	var b strings.Builder
	b.WriteString("📊 *Stock disponible*\n_uniques · non livrés_\n\n")
	total := 0
	for _, p := range list {
		fmt.Fprintf(&b, "%s `%s` — *%d*\n", providerEmoji(p.Provider), p.Provider, p.Count)
		total += p.Count
	}
	fmt.Fprintf(&b, "\n━━━━━━━━━━━━━━━━\n🎯 *Total : %d emails*", total)
	return b.String()
}

func extractMenuText() string {
	return "🗂️ *Choisis un fournisseur*\n\n👇 Sélectionne le service :"
}

func quantityAskText(provider string) string {
	return fmt.Sprintf("%s *%s* sélectionné\n\n🔢 Envoie un *chiffre* — combien d'emails ?", providerEmoji(provider), provider)
}

func invalidQtyText(provider string) string {
	return fmt.Sprintf("⚠️ Nombre invalide.\n\nEnvoie un chiffre pour *%s* (ex: `100`)", provider)
}

func emptyStockText() string {
	return "📭 *Stock vide*\n\nAucun email dispo pour le moment."
}

func accessDeniedText(userID int64) string {
	return fmt.Sprintf("🚫 *Accès refusé*\n\n🆔 Ton ID : `%d`\n\nEnvoie /myid pour l'ajouter à la whitelist.", userID)
}

func myIDText(userID int64) string {
	return fmt.Sprintf("🆔 *Ton ID Telegram*\n\n`%d`\n\n➕ Ajoute-le dans `TELEGRAM_ALLOWED_IDS`", userID)
}

func hintText() string {
	return "👆 Tape /start puis choisis un fournisseur."
}

func extractionLaunchText(provider string, count int) string {
	return fmt.Sprintf("⚡ *Extraction lancée*\n\n%s `%s` · *%d* emails\n\n⏳ Préparation en cours…", providerEmoji(provider), provider, count)
}

func deliveryCaption(provider string, count int) string {
	return fmt.Sprintf("✅ *%d emails* livrés\n%s `%s`\n\n🗑️ Retirés du stock", count, providerEmoji(provider), provider)
}

func callbackDenied() string  { return "🚫 Accès refusé" }
func callbackEmpty() string   { return "📭 Stock vide" }
func callbackSending() string { return "⚡ Envoi en cours…" }
func callbackError() string   { return "❌ Erreur" }
func callbackBadQty() string  { return "⚠️ Quantité invalide" }

func btnExtract() string { return "📥 Extraire" }
func btnBack() string    { return "◀️ Retour" }

func providerButtonLabel(provider string, count int) string {
	return fmt.Sprintf("%s %s · %d", providerEmoji(provider), provider, count)
}
