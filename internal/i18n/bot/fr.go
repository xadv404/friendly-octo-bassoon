package bot

import "fmt"

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
	return "👆 Tape /start puis choisis un fournisseur."
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
