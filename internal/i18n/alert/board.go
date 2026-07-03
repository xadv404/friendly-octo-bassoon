package alert

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

const (
	MaxBoardVulns  = 12
	MaxBoardEmails = 6
)

// BoardState état affiché dans le message live Telegram.
type BoardState struct {
	Title    string
	Subtitle string
	Phase    string // discover, fresh-pass, scan, done, no-new, error

	DiscoverLabel string
	DorkStep      int
	DorkTotal     int
	Kept          int
	Fetched       int
	Skipped       int
	DiscoverDone  bool

	Scanned    int
	ScanTotal  int
	Vulns      int
	Findings   int
	DumpsOK    int
	DumpFails  int
	NewEmails  int
	ScanDone   bool
	Stock      string
	Detail     string

	VulnsList  []models.Finding
	EmailsList []string
	Error      string
}

// RenderBoard formate le message live (plain text, pas Markdown).
func RenderBoard(loc string, st BoardState) string {
	l := labelsForBoard(loc)
	var b strings.Builder

	b.WriteString("sqli-hunter")
	if st.Title != "" {
		b.WriteString(" · ")
		b.WriteString(st.Title)
	}
	b.WriteString("\n")
	b.WriteString("────────────────────\n")

	if st.Error != "" {
		b.WriteString("❌ ")
		b.WriteString(st.Error)
		b.WriteString("\n\n")
	}

	if st.Subtitle != "" {
		b.WriteString(st.Subtitle)
		b.WriteString("\n\n")
	}

	b.WriteString(renderDiscoverSection(l, st))
	b.WriteString("\n\n")
	b.WriteString(renderScanSection(l, st))

	if len(st.VulnsList) > 0 {
		b.WriteString("\n\n")
		b.WriteString(l.vulnsHeader)
		b.WriteString("\n")
		for _, f := range st.VulnsList {
			b.WriteString("• ")
			b.WriteString(shortVulnLine(f))
			b.WriteString("\n")
		}
		if st.Vulns > len(st.VulnsList) {
			b.WriteString(fmt.Sprintf(l.vulnsMore, st.Vulns-len(st.VulnsList)))
			b.WriteString("\n")
		}
	}

	if len(st.EmailsList) > 0 {
		b.WriteString("\n\n")
		b.WriteString(l.emailsHeader)
		b.WriteString("\n")
		for _, em := range st.EmailsList {
			b.WriteString("✉ ")
			b.WriteString(em)
			b.WriteString("\n")
		}
	}

	if st.ScanDone || st.Phase == "no-new" || st.Phase == "done" {
		if st.Detail != "" {
			b.WriteString("\n\n")
			b.WriteString(st.Detail)
		}
		if st.Stock != "" {
			b.WriteString("\n\n")
			b.WriteString(st.Stock)
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

type boardL10n struct {
	discoverActive, discoverDone, discoverWait string
	scanActive, scanDone, scanWait               string
	scanWaitLine                                 string
	dorks, pages, urls                           string
	vulnsHeader, vulnsMore                       string
	dumpsLine                                    string
	emailsHeader                                 string
}

func labelsForBoard(loc string) boardL10n {
	if loc == "en" {
		return boardL10n{
			discoverActive: "◉ Discover",
			discoverDone:   "✓ Discover",
			discoverWait:   "◯ Discover",
			scanActive:     "◉ Scan",
			scanDone:       "✓ Scan",
			scanWait:       "◯ Scan",
			scanWaitLine:   "waiting…",
			dorks:          "dorks",
			pages:          "pages",
			urls:           "URLs",
			vulnsHeader:    "Vulnerabilities",
			vulnsMore:      "… +%d more",
			dumpsLine:      "dumps: %d OK · %d failed",
			emailsHeader:   "New emails",
		}
	}
	return boardL10n{
		discoverActive: "◉ Discover",
		discoverDone:   "✓ Discover",
		discoverWait:   "◯ Discover",
		scanActive:     "◉ Scan",
		scanDone:       "✓ Scan",
		scanWait:       "◯ Scan",
		scanWaitLine:   "en attente…",
		dorks:          "dorks",
		pages:          "pages",
		urls:           "URLs",
		vulnsHeader:    "Vulnérabilités",
		vulnsMore:      "… +%d autres",
		dumpsLine:      "dumps : %d OK · %d échecs",
		emailsHeader:   "Nouveaux emails",
	}
}

func renderDiscoverSection(l boardL10n, st BoardState) string {
	var b strings.Builder
	switch {
	case st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" || st.Phase == "no-new":
		b.WriteString(l.discoverDone)
	case st.Phase == "discover" || st.Phase == "fresh-pass":
		b.WriteString(l.discoverActive)
	default:
		b.WriteString(l.discoverWait)
	}

	if st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" || st.Phase == "no-new" {
		b.WriteString("\n")
		if st.DorkTotal > 0 {
			b.WriteString(fmt.Sprintf("%d %s · %d %s gardées",
				max(st.DorkStep, st.DorkTotal), l.dorks, st.Kept, l.urls))
		} else if st.DorkStep > 0 {
			b.WriteString(fmt.Sprintf("%d %s · %d %s gardées",
				st.DorkStep, l.pages, st.Kept, l.urls))
		} else {
			b.WriteString(fmt.Sprintf("%d gardées · %d lues", st.Kept, st.Fetched))
		}
		if st.Skipped > 0 {
			b.WriteString(fmt.Sprintf(" · %d ignorées", st.Skipped))
		}
		return b.String()
	}

	if st.Phase == "discover" || st.Phase == "fresh-pass" {
		b.WriteString("\n")
		if st.DiscoverLabel != "" {
			b.WriteString(st.DiscoverLabel)
			b.WriteString("\n")
		}
		if st.DorkTotal > 0 {
			b.WriteString(progressBar(st.DorkStep, st.DorkTotal))
			b.WriteString(fmt.Sprintf(" %d/%d %s", st.DorkStep, st.DorkTotal, l.dorks))
		} else if st.DorkStep > 0 {
			b.WriteString(progressBar(st.DorkStep, 0))
			b.WriteString(fmt.Sprintf(" %s %d", l.pages, st.DorkStep))
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%d gardées · %d lues", st.Kept, st.Fetched))
		if st.Skipped > 0 {
			b.WriteString(fmt.Sprintf(" · %d ignorées", st.Skipped))
		}
		return b.String()
	}

	b.WriteString("\n")
	b.WriteString("…")
	return b.String()
}

func renderScanSection(l boardL10n, st BoardState) string {
	var b strings.Builder
	switch {
	case st.ScanDone || st.Phase == "done":
		b.WriteString(l.scanDone)
	case st.Phase == "scan":
		b.WriteString(l.scanActive)
	default:
		b.WriteString(l.scanWait)
	}

	if st.ScanTotal <= 0 && st.Phase != "scan" && !st.ScanDone {
		b.WriteString("\n")
		b.WriteString(l.scanWaitLine)
		return b.String()
	}

	b.WriteString("\n")
	if st.ScanTotal > 0 {
		b.WriteString(progressBar(st.Scanned, st.ScanTotal))
		b.WriteString(fmt.Sprintf(" %d/%d", st.Scanned, st.ScanTotal))
	} else if st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("%d scannées", st.Scanned))
	}

	if st.Vulns > 0 || st.Findings > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%d vuln · %d findings", st.Vulns, st.Findings))
	}
	if st.Findings > 0 || st.DumpsOK > 0 || st.DumpFails > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf(l.dumpsLine, st.DumpsOK, st.DumpFails))
	}
	if st.NewEmails > 0 && (st.ScanDone || st.Phase == "done") {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("+%d nouveaux emails", st.NewEmails))
	}

	return b.String()
}

func progressBar(step, total int) string {
	const width = 16
	if step <= 0 {
		return "[" + strings.Repeat("░", width) + "]"
	}
	filled := width
	if total > 0 {
		filled = step * width / total
		if filled > width {
			filled = width
		}
		if filled < 1 && step > 0 {
			filled = 1
		}
	}
	return "[" + strings.Repeat("█", filled) + strings.Repeat("░", width-filled) + "]"
}

func shortVulnLine(f models.Finding) string {
	u := truncURL(f.URL, 72)
	if f.Parameter != "" {
		return string(f.VulnType) + " · " + u + " · " + f.Parameter
	}
	return string(f.VulnType) + " · " + u
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
