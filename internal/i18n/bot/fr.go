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

	ScanUsage:          frScanUsage,
	ScanStarted:        frScanStarted,
	ScanAlreadyRunning: frScanAlreadyRunning,
	ScanStopped:        frScanStopped,
	ScanStopIdle:       frScanStopIdle,
	ScanError:          frScanError,

	ScanAskScope:       frScanAskScope,
	ScanScopeBadFile:   frScanScopeBadFile,
	ScanScopeError:     frScanScopeError,
	ScanScopeNoPending: frScanScopeNoPending,
	ScanScopeStarted:   frScanScopeStarted,

	BtnScanStart: frBtnScanStart,
	BtnScanStop:    frBtnScanStop,
	BtnDorks:       frBtnDorks,

	DorksSent:  frDorksSent,
	DorksError: frDorksError,
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
	return "👆 /start — export emails\n📋 /dorks — fichier dorks\n▶️ /scan hunt — lancer scan\n⏹ /stop — arrêter"
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
	if st.ScanTotal > 0 || st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("📊 scanné : %d/%d\n", st.Scanned, st.ScanTotal))
		b.WriteString(fmt.Sprintf("🔴 vulnérable : %d\n", st.Vulns))
		b.WriteString(fmt.Sprintf("🔎 findings : %d", st.Findings))
	} else {
		b.WriteString(fmt.Sprintf("📌 URLs : %d\n", scopeN))
		b.WriteString(fmt.Sprintf("✅ scannées : %d", scannedN))
	}
	if updatedAgo != "" {
		b.WriteString(fmt.Sprintf("\n_%s_", updatedAgo))
	}
	return b.String()
}

func frScanUsage() string {
	return "▶️ `/scan hunt` — lance le scan\n\n📋 `/dorks` — exporter les dorks\n⏹ `/stop` — arrêter"
}

func frScanStarted(tier, pid, log string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("✅ *Scan %s lancé*", tier))
	if pid != "" {
		b.WriteString(fmt.Sprintf("\nPID `%s`", pid))
	}
	if log != "" {
		b.WriteString(fmt.Sprintf("\nlog `%s`", log))
	}
	return b.String()
}

func frScanAlreadyRunning(tier string) string {
	return fmt.Sprintf("⚠️ Un scan *%s* tourne déjà.\n\n⏹ `/stop` pour arrêter.", tier)
}

func frScanStopped(_ string) string {
	return "⏹ Scan arrêté"
}

func frScanStopIdle() string {
	return "ℹ️ Aucun scan en cours."
}

func frScanError(msg string) string {
	return "❌ " + msg
}

func frScanAskScope() string {
	return "📎 Pas de scope — envoie le `.txt` des URLs"
}

func frScanScopeBadFile() string {
	return "⚠️ Fichier invalide — envoie un `.txt` avec les URLs."
}

func frScanScopeError(err string) string {
	return "❌ Fichier scope: " + err
}

func frScanScopeNoPending() string {
	return "ℹ️ Lance d'abord `/scan hunt`, puis envoie le `.txt`."
}

func frScanScopeStarted(urlCount int) string {
	return fmt.Sprintf("▶️ %d URLs · scan lancé", urlCount)
}

func frBtnScanStart() string { return "▶️ Lancer hunt" }
func frBtnScanStop() string    { return "⏹ Stop" }
func frBtnDorks() string       { return "📋 Générer dorks" }

func frDorksSent(count int) string {
	return fmt.Sprintf("📋 %d dorks top · 1/ligne · 1ère page Google", count)
}

func frDorksError(err string) string {
	return "❌ Dorks: " + err
}
