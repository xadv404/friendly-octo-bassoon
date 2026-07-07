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

	ScanUsage:          enScanUsage,
	ScanStarted:        enScanStarted,
	ScanAlreadyRunning: enScanAlreadyRunning,
	ScanStopped:        enScanStopped,
	ScanStopIdle:       enScanStopIdle,
	ScanError:          enScanError,

	ScanAskScope:       enScanAskScope,
	ScanScopeBadFile:   enScanScopeBadFile,
	ScanScopeError:     enScanScopeError,
	ScanScopeNoPending: enScanScopeNoPending,
	ScanScopeStarted:   enScanScopeStarted,

	BtnScanStart: enBtnScanStart,
	BtnScanStop:    enBtnScanStop,

	DorksSent:  enDorksSent,
	DorksError: enDorksError,
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
	return "👆 /start — export emails\n📊 /status — progress\n📋 /dorks — dorks file\n▶️ /scan hunt — scan URLs\n⏹ /stop — stop"
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
	if st.ScanTotal > 0 || st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("🛡 %d/%d · 🔴 %d · 🔎 %d", st.Scanned, st.ScanTotal, st.Vulns, st.Findings))
	} else {
		b.WriteString(fmt.Sprintf("📌 %d URLs · ✅ %d scanned", scopeN, scannedN))
	}
	if updatedAgo != "" {
		b.WriteString(fmt.Sprintf("\n_%s_", updatedAgo))
	}
	return b.String()
}

func enScanUsage() string {
	return "▶️ *Start hunt*\n\n`/scan hunt` — then send the URLs `.txt`\n\n📋 `/dorks` — export dorks\n⏹ `/stop` — stop"
}

func enScanStarted(tier, pid, log string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("✅ *Scan %s started*", tier))
	if pid != "" {
		b.WriteString(fmt.Sprintf("\nPID `%s`", pid))
	}
	if log != "" {
		b.WriteString(fmt.Sprintf("\nlog `%s`", log))
	}
	return b.String()
}

func enScanAlreadyRunning(tier string) string {
	return fmt.Sprintf("⚠️ A *%s* scan is already running.\n\n⏹ `/stop` to stop it.", tier)
}

func enScanStopped(_ string) string {
	return "⏹ Scan stopped"
}

func enScanStopIdle() string {
	return "ℹ️ No scan running."
}

func enScanError(msg string) string {
	return "❌ " + msg
}

func enScanAskScope() string {
	return "📎 Send the URLs `.txt` (1 per line)"
}

func enScanScopeBadFile() string {
	return "⚠️ Invalid file — send a `.txt` with URLs."
}

func enScanScopeError(err string) string {
	return "❌ Scope file: " + err
}

func enScanScopeNoPending() string {
	return "ℹ️ Run `/scan hunt` first, then send the `.txt`."
}

func enScanScopeStarted(urlCount int) string {
	return fmt.Sprintf("▶️ %d URLs · scan started", urlCount)
}

func enBtnScanStart() string { return "▶️ Start hunt" }
func enBtnScanStop() string    { return "⏹ Stop" }

func enDorksSent(count int) string {
	return fmt.Sprintf("📋 %d top dorks · 1/line · page 1 Google", count)
}

func enDorksError(err string) string {
	return "❌ Dorks: " + err
}
