package alert

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// Texts messages d'alerte scan (sqli-hunter daily).
type Texts struct {
	TitleDailyLaunch   string
	TitleScanComplete  string
	TitleDailyComplete string

	Launch        func(title, detail string) string
	DiscoverDone  func(kept, skipped, fetched int) string
	ScanStarted   func(urlCount int, listFile string) string
	Vuln          func(f models.Finding) string
	DumpFail      func(f models.Finding, reason string) string
	DumpOK        func(d models.ExtractedData, email string) string
	Complete      func(title, detail string) string
	Error         func(msg string) string
	StockSummary  func(baseDir string) string
	DailyLaunch   func(limit, threads int, outputDir string) string
	DailyNoNew    func(baseDir string) string
	DiscoverProgress func(phase string, step, total, kept, fetched, skipped int) string
	ScanProgress  func(scanned, total, vulns, findings int) string
}

// For retourne les textes notify pour une locale (fr, en).
func For(loc string) Texts {
	if loc == "en" {
		return en
	}
	return fr
}

func stockLines(baseDir string, header, lineFmt, empty string) string {
	list, err := results.ListProviders(baseDir)
	if err != nil || len(list) == 0 {
		return empty
	}
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("\n")
	for _, p := range list {
		b.WriteString(fmt.Sprintf(lineFmt, p.Provider, p.Count))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func formatScanComplete(scanned, total, vulns, findings, newEmails int, stock string, labels scanCompleteLabels) string {
	return strings.Join([]string{
		labels.scanned + fmt.Sprintf(" %d/%d", scanned, total),
		labels.vulns + fmt.Sprintf(" %d", vulns),
		labels.findings + fmt.Sprintf(" %d", findings),
		labels.newEmails + fmt.Sprintf(" %d", newEmails),
		"",
		stock,
	}, "\n")
}

type scanCompleteLabels struct {
	scanned, vulns, findings, newEmails string
}
