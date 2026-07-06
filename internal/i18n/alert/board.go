package alert

import (
	"fmt"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

const (
	MaxBoardVulns  = 10
	MaxBoardEmails = 8
	MaxBoardURLs   = 8
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

	URLsList   []string
	VulnsList  []models.Finding
	EmailsList []string
	Error      string
}

// RenderBoard formate le message live (plain text, pas Markdown).
func RenderBoard(loc string, st BoardState) string {
	l := labelsForBoard(loc)
	var b strings.Builder

	b.WriteString("🎯 SQLi Hunter")
	if st.Title != "" {
		b.WriteString("\n")
		b.WriteString(modeEmoji(st.Title))
		b.WriteString(" ")
		b.WriteString(st.Title)
	}
	b.WriteString("\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━\n")

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

	if len(st.URLsList) > 0 && (st.Phase == "discover" || st.Phase == "fresh-pass" || !st.DiscoverDone) {
		b.WriteString("\n\n")
		b.WriteString(l.urlsHeader)
		b.WriteString("\n")
		for _, u := range st.URLsList {
			b.WriteString("  🔗 ")
			b.WriteString(compactURL(u, 58))
			b.WriteString("\n")
		}
		if st.Kept > len(st.URLsList) {
			b.WriteString(fmt.Sprintf(l.urlsMore, st.Kept-len(st.URLsList)))
			b.WriteString("\n")
		}
	}

	b.WriteString("\n\n")
	b.WriteString(renderScanSection(l, st))

	if len(st.VulnsList) > 0 {
		b.WriteString("\n\n")
		b.WriteString(l.vulnsHeader)
		b.WriteString("\n")
		for _, f := range st.VulnsList {
			b.WriteString("  ")
			b.WriteString(vulnEmoji(f.VulnType))
			b.WriteString(" ")
			b.WriteString(shortVulnLine(f))
			b.WriteString("\n")
		}
		if st.Vulns > len(st.VulnsList) {
			b.WriteString(fmt.Sprintf("  "+l.vulnsMore, st.Vulns-len(st.VulnsList)))
			b.WriteString("\n")
		}
	}

	if len(st.EmailsList) > 0 {
		b.WriteString("\n\n")
		b.WriteString(l.emailsHeader)
		b.WriteString("\n")
		for _, em := range st.EmailsList {
			b.WriteString("  ✉️ ")
			b.WriteString(em)
			b.WriteString("\n")
		}
	}

	if st.ScanDone || st.Phase == "no-new" || st.Phase == "done" {
		if st.Detail != "" {
			b.WriteString("\n\n")
			b.WriteString("🏁 ")
			b.WriteString(st.Detail)
		}
		if st.Stock != "" {
			b.WriteString("\n\n")
			b.WriteString("📦 ")
			b.WriteString(st.Stock)
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

type boardL10n struct {
	discoverHeader, discoverDone, discoverWait string
	freshPass                                  string
	scanHeader, scanDone, scanWait             string
	scanWaitLine                               string
	dorks, pages                               string
	statsKept, statsFetched, statsSkipped      string
	urlsHeader, urlsMore                       string
	vulnsHeader, vulnsMore                     string
	dumpsLine                                  string
	emailsHeader                             string
}

func labelsForBoard(loc string) boardL10n {
	if loc == "en" {
		return boardL10n{
			discoverHeader: "🔍 DISCOVERY",
			discoverDone:   "✅ Discovery done",
			discoverWait:   "🔍 Discovery",
			freshPass:      "⚡ Fresh pass",
			scanHeader:     "🛡 SCAN",
			scanDone:       "✅ Scan done",
			scanWait:       "🛡 SCAN",
			scanWaitLine:   "⏳ Waiting…",
			dorks:          "dorks",
			pages:          "pages",
			statsKept:      "📌 %d URLs",
			statsFetched:   "📥 %d fetched",
			statsSkipped:   "⏭ %d skipped",
			urlsHeader:     "🔗 Latest URLs",
			urlsMore:       "… +%d more",
			vulnsHeader:    "🔥 Vulnerabilities",
			vulnsMore:      "… +%d more",
			dumpsLine:      "💾 dumps: %d OK · %d failed",
			emailsHeader:   "📬 New emails",
		}
	}
	return boardL10n{
		discoverHeader: "🔍 DÉCOUVERTE",
		discoverDone:   "✅ Découverte terminée",
		discoverWait:   "🔍 Découverte",
		freshPass:      "⚡ Fresh pass",
		scanHeader:     "🛡 SCAN",
		scanDone:       "✅ Scan terminé",
		scanWait:       "🛡 SCAN",
		scanWaitLine:   "⏳ En attente…",
		dorks:          "dorks",
		pages:          "pages",
		statsKept:      "📌 %d URLs",
		statsFetched:   "📥 %d lues",
		statsSkipped:   "⏭ %d ignorées",
		urlsHeader:     "🔗 Dernières URLs",
		urlsMore:       "… +%d autres",
		vulnsHeader:    "🔥 Vulnérabilités",
		vulnsMore:      "… +%d autres",
		dumpsLine:      "💾 dumps : %d OK · %d échecs",
		emailsHeader:   "📬 Nouveaux emails",
	}
}

func renderDiscoverSection(l boardL10n, st BoardState) string {
	var b strings.Builder
	switch {
	case st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" || st.Phase == "no-new":
		b.WriteString(l.discoverDone)
	case st.Phase == "discover" || st.Phase == "fresh-pass":
		b.WriteString(l.discoverHeader)
	default:
		b.WriteString(l.discoverWait)
	}

	if st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" || st.Phase == "no-new" {
		b.WriteString("\n")
		b.WriteString(renderDiscoverStats(l, st))
		return b.String()
	}

	if st.Phase == "discover" || st.Phase == "fresh-pass" {
		b.WriteString("\n")
		if st.Phase == "fresh-pass" {
			b.WriteString(l.freshPass)
		} else if st.DiscoverLabel != "" {
			b.WriteString(st.DiscoverLabel)
		}
		if st.DorkTotal > 0 || st.DorkStep > 0 {
			b.WriteString("\n")
			if st.DorkTotal > 0 {
				b.WriteString(progressBar(st.DorkStep, st.DorkTotal))
				b.WriteString(fmt.Sprintf(" %d/%d %s", st.DorkStep, st.DorkTotal, l.dorks))
			} else {
				b.WriteString(progressBar(st.DorkStep, 0))
				b.WriteString(fmt.Sprintf(" %s %d", l.pages, st.DorkStep))
			}
		}
		b.WriteString("\n")
		b.WriteString(renderDiscoverStats(l, st))
		return b.String()
	}

	b.WriteString("\n⏳ …")
	return b.String()
}

func renderDiscoverStats(l boardL10n, st BoardState) string {
	parts := []string{fmt.Sprintf(l.statsKept, st.Kept), fmt.Sprintf(l.statsFetched, st.Fetched)}
	if st.Skipped > 0 {
		parts = append(parts, fmt.Sprintf(l.statsSkipped, st.Skipped))
	}
	return strings.Join(parts, " · ")
}

func renderScanSection(l boardL10n, st BoardState) string {
	var b strings.Builder
	switch {
	case st.ScanDone || st.Phase == "done":
		b.WriteString(l.scanDone)
	case st.Phase == "scan":
		b.WriteString(l.scanHeader)
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
		b.WriteString(fmt.Sprintf(" %d/%d URLs", st.Scanned, st.ScanTotal))
	} else if st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("📊 %d scannées", st.Scanned))
	}

	if st.Vulns > 0 || st.Findings > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("🔴 %d vuln · 🔎 %d findings", st.Vulns, st.Findings))
	}
	if st.DumpsOK > 0 || st.DumpFails > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf(l.dumpsLine, st.DumpsOK, st.DumpFails))
	}
	if st.NewEmails > 0 && (st.ScanDone || st.Phase == "done") {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("📬 +%d nouveaux emails", st.NewEmails))
	}

	return b.String()
}

func progressBar(step, total int) string {
	const width = 14
	if step <= 0 {
		return "░" + strings.Repeat("░", width-1)
	}
	filled := width
	if total > 0 {
		filled = step * width / total
		if filled > width {
			filled = width
		}
		if filled < 1 {
			filled = 1
		}
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func shortVulnLine(f models.Finding) string {
	u := compactURL(f.URL, 52)
	if f.Parameter != "" {
		return fmt.Sprintf("%s · ?%s", u, f.Parameter)
	}
	return u
}

func compactURL(u string, max int) string {
	u = strings.TrimSpace(u)
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	return truncURL(u, max)
}

func modeEmoji(title string) string {
	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "monthly"), strings.Contains(lower, "mensuel"):
		return "📅"
	case strings.Contains(lower, "weekly"), strings.Contains(lower, "hebdo"):
		return "📆"
	case strings.Contains(lower, "daily"), strings.Contains(lower, "quotid"):
		return "☀️"
	default:
		return "🚀"
	}
}

func vulnEmoji(t models.VulnType) string {
	switch t {
	case models.SQLiError:
		return "💥"
	case models.SQLiUnion:
		return "🔗"
	case models.SQLiBoolean:
		return "🎭"
	case models.SQLiTime:
		return "⏱️"
	case models.NoSQL:
		return "🍃"
	default:
		return "🔴"
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
