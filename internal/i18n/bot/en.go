package bot

import "fmt"

const nameEN = "MAIL LIST"

var en = Texts{
	BotName: nameEN,

	Welcome:       enWelcome,
	StockEmpty:    enStockEmpty,
	StockHeader:   enStockHeader,
	StockLine:     enStockLine,
	StockTotal:    enStockTotal,
	ExtractMenu:   enExtractMenu,
	QuantityAsk:   enQuantityAsk,
	InvalidQty:    enInvalidQty,
	Hint:          enHint,
	Delivery:      enDelivery,
	MaxEmails:     enMaxEmails,
	WriteError:    enWriteError,
	SendError:     enSendError,
	TakeError:     enTakeError,
	AccessDenied:  enAccessDenied,
	MyID:          enMyID,
	BtnExtract:    enBtnExtract,
	BtnBack:       enBtnBack,
	ProviderLabel: enProviderLabel,
	CallbackDenied: enCallbackDenied,
	CallbackEmpty:  enCallbackEmpty,
}

func enWelcome(stock string) string {
	return fmt.Sprintf("🇨🇭 *%s*\n_.ch email stock — instant export_\n\n%s", nameEN, stock)
}

func enStockEmpty() string {
	return "📭 *Empty stock*\n\nNo emails available right now."
}

func enStockHeader() string {
	return "📊 *Available stock*\n_unique · not delivered_\n\n"
}

func enStockLine(emoji, provider string, count int) string {
	return fmt.Sprintf("%s `%s` — *%d*\n", emoji, provider, count)
}

func enStockTotal(total int) string {
	return fmt.Sprintf("\n━━━━━━━━━━━━━━━━\n🎯 *Total: %d emails*", total)
}

func enExtractMenu() string {
	return "🗂️ *Pick a provider*\n\n👇 Select a service:"
}

func enQuantityAsk(emoji, provider string) string {
	return fmt.Sprintf("%s *%s* selected\n\n🔢 Send a *number* — how many emails?", emoji, provider)
}

func enInvalidQty(provider string) string {
	return fmt.Sprintf("⚠️ Invalid number.\n\nSend a number for *%s* (e.g. `100`)", provider)
}

func enHint() string {
	return "👆 Type /start then pick a provider."
}

func enDelivery(emoji, provider string, count int) string {
	return fmt.Sprintf("✅ *%d emails* delivered\n%s `%s`\n\n🗑️ Removed from stock", count, emoji, provider)
}

func enMaxEmails(max int) string {
	return fmt.Sprintf("⚠️ Max *%d* emails per request.", max)
}

func enWriteError() string  { return "❌ File write error." }
func enSendError(err string) string { return "❌ Send failed: " + err }
func enTakeError(err string) string  { return "❌ " + err }

func enAccessDenied(userID int64) string {
	return fmt.Sprintf("🚫 *Access denied*\n\n🆔 Your ID: `%d`\n\nSend /myid to add it to the whitelist.", userID)
}

func enMyID(userID int64) string {
	return fmt.Sprintf("🆔 *Your Telegram ID*\n\n`%d`\n\n➕ Add it to `TELEGRAM_ALLOWED_IDS`", userID)
}

func enBtnExtract() string { return "📥 Extract" }
func enBtnBack() string    { return "◀️ Back" }

func enProviderLabel(emoji, provider string, count int) string {
	return fmt.Sprintf("%s %s · %d", emoji, provider, count)
}

func enCallbackDenied() string { return "🚫 Access denied" }
func enCallbackEmpty() string  { return "📭 Empty stock" }
