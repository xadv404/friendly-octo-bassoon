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
	Phase string // discover, fresh-pass, scan, done, no-new, error

	DiscoverLabel string
	DorkStep      int
	DorkTotal     int
	Kept          int
	Fetched       int
	Skipped       int
	DiscoverDone  bool

	Scanned   int
	ScanTotal int
	Vulns     int
	Findings  int
	DumpsOK   int
	DumpFails int
	NewEmails int
	ScanDone  bool
	Stock     string
	Detail    string

	URLsList   []string
	VulnsList  []models.Finding
	EmailsList []string
	Error      string
}

// RenderBoard formate le message live complet (rétrocompat tests).
func RenderBoard(loc string, st BoardState) string {
	if st.Phase == "scan" || st.Phase == "done" || st.ScanDone {
		return RenderScanBoard(loc, st)
	}
	return RenderDiscoverBoard(loc, st)
}

// RenderDiscoverBoard — message live pendant la découverte uniquement.
func RenderDiscoverBoard(loc string, st BoardState) string {
	l := labelsForBoard(loc)
	var b strings.Builder

	b.WriteString("🎯 SQLi Hunter\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━")

	if st.Error != "" {
		b.WriteString("\n\n❌ ")
		b.WriteString(st.Error)
	}

	b.WriteString("\n\n")
	b.WriteString(renderDiscoverSection(l, st))

	if len(st.URLsList) > 0 {
		b.WriteString("\n\n")
		b.WriteString(l.urlsHeader)
		b.WriteString("\n")
		for _, u := range st.URLsList {
			b.WriteString("  🔗 ")
			b.WriteString(compactURL(u, 58))
			b.WriteString("\n")
		}
		if st.Kept > len(st.URLsList) {
			b.WriteString(fmt.Sprintf("  "+l.urlsMore, st.Kept-len(st.URLsList)))
			b.WriteString("\n")
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

// RenderScanBoard — message live pendant le scan (nouveau message après discover).
func RenderScanBoard(loc string, st BoardState) string {
	l := labelsForBoard(loc)
	var b strings.Builder

	b.WriteString("🎯 SQLi Hunter\n")
	b.WriteString("━━━━━━━━━━━━━━━━━━━━")

	if st.Error != "" {
		b.WriteString("\n\n❌ ")
		b.WriteString(st.Error)
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

	if st.ScanDone || st.Phase == "done" {
		if st.Detail != "" {
			b.WriteString("\n\n🏁 ")
			b.WriteString(st.Detail)
		}
		if st.Stock != "" {
			b.WriteString("\n\n📦 ")
			b.WriteString(st.Stock)
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

type boardL10n struct {
	discoverHeader, discoverDone string
	freshPass, discoverMain      string
	scanHeader, scanDone, scanWait string
	scanWaitLine                 string
	dorks, pages                 string
	statsKept                    string
	urlsHeader, urlsMore         string
	vulnsHeader, vulnsMore       string
	dumpsLine                    string
	emailsHeader                 string
}

func labelsForBoard(loc string) boardL10n {
	if loc == "en" {
		return boardL10n{
			discoverHeader: "🔍 DISCOVERY",
			discoverDone:   "✅ Discovery done",
			freshPass:      "⚡ Fresh pass",
			discoverMain:   "🌐 Discover",
			scanHeader:     "🛡 SCAN",
			scanDone:       "✅ Scan done",
			scanWait:       "🛡 SCAN",
			scanWaitLine:   "⏳ Waiting…",
			dorks:          "dorks",
			pages:          "pages",
			statsKept:      "📌 %d URLs",
			urlsHeader:     "🔗 Latest URLs",
			urlsMore:       "… +%d more",
			vulnsHeader:    "🔥 Vulnerabilities",
			vulnsMore:      "… +%d more",
			dumpsLine:      "💾 %d OK · %d failed",
			emailsHeader:   "📬 New emails",
		}
	}
	return boardL10n{
		discoverHeader: "🔍 DÉCOUVERTE",
		discoverDone:   "✅ Terminée",
		freshPass:      "⚡ Fresh pass",
		discoverMain:   "🌐 Discover",
		scanHeader:     "🛡 SCAN",
		scanDone:       "✅ Terminé",
		scanWait:       "🛡 SCAN",
		scanWaitLine:   "⏳ En attente…",
		dorks:          "dorks",
		pages:          "pages",
		statsKept:      "📌 %d URLs",
		urlsHeader:     "🔗 Dernières URLs",
		urlsMore:       "… +%d autres",
		vulnsHeader:    "🔥 Vulnérabilités",
		vulnsMore:      "… +%d autres",
		dumpsLine:      "💾 %d OK · %d échecs",
		emailsHeader:   "📬 Nouveaux emails",
	}
}

func renderDiscoverSection(l boardL10n, st BoardState) string {
	var b strings.Builder
	showProgress := st.Phase == "discover" || st.Phase == "fresh-pass" || st.Phase == "error"
	switch {
	case st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" || st.Phase == "no-new":
		b.WriteString(l.discoverHeader)
		b.WriteString("\n")
		b.WriteString(l.discoverDone)
	case st.Phase == "fresh-pass":
		b.WriteString(l.discoverHeader)
		b.WriteString("\n")
		b.WriteString(l.freshPass)
	case st.Phase == "discover" || st.Phase == "error":
		b.WriteString(l.discoverHeader)
		b.WriteString("\n")
		b.WriteString(l.discoverMain)
	default:
		b.WriteString(l.discoverHeader)
	}

	if st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" || st.Phase == "no-new" {
		b.WriteString("\n")
		if st.DorkTotal > 0 {
			b.WriteString(fmt.Sprintf("📌 %d URLs · %d/%d %s", st.Kept, max(st.DorkStep, st.DorkTotal), st.DorkTotal, l.dorks))
		} else {
			b.WriteString(fmt.Sprintf(l.statsKept, st.Kept))
		}
		return b.String()
	}

	if showProgress {
		if st.DorkTotal > 0 || st.DorkStep > 0 {
			b.WriteString("\n")
			if st.DorkTotal > 0 {
				b.WriteString(progressBar(st.DorkStep, st.DorkTotal))
				b.WriteString(fmt.Sprintf(" %d/%d %s", st.DorkStep, st.DorkTotal, l.dorks))
			} else {
				b.WriteString(progressBar(st.DorkStep, 0))
				b.WriteString(fmt.Sprintf(" %s %d", l.pages, st.DorkStep))
			}
		} else {
			b.WriteString("\n⏳ Démarrage…")
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf(l.statsKept, st.Kept))
		if st.Fetched > 0 {
			b.WriteString(fmt.Sprintf(" · %d lues", st.Fetched))
		}
		return b.String()
	}

	b.WriteString("\n⏳ Démarrage…")
	return b.String()
}

func renderScanSection(l boardL10n, st BoardState) string {
	var b strings.Builder
	switch {
	case st.ScanDone || st.Phase == "done":
		b.WriteString(l.scanDone)
	case st.Phase == "scan":
		b.WriteString(l.scanHeader)
	default:
		b.WriteString(l.scanHeader)
	}

	if st.Kept > 0 && (st.Phase == "scan" || st.ScanDone || st.Phase == "done") {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf(l.statsKept, st.Kept))
	}

	if st.ScanTotal <= 0 && st.Phase == "scan" && st.Scanned == 0 {
		b.WriteString("\n")
		b.WriteString(l.scanWaitLine)
		return b.String()
	}

	b.WriteString("\n")
	if st.ScanTotal > 0 {
		b.WriteString(progressBar(st.Scanned, st.ScanTotal))
		b.WriteString(fmt.Sprintf(" %d/%d URLs", st.Scanned, st.ScanTotal))
	} else if st.Scanned > 0 {
		b.WriteString(fmt.Sprintf("📊 %d", st.Scanned))
	}

	if st.Vulns > 0 || st.Findings > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("🔴 %d vuln · 🔎 %d", st.Vulns, st.Findings))
	}
	if st.DumpsOK > 0 || st.DumpFails > 0 {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf(l.dumpsLine, st.DumpsOK, st.DumpFails))
	}
	if st.NewEmails > 0 && (st.ScanDone || st.Phase == "done") {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("📬 +%d emails", st.NewEmails))
	}

	return b.String()
}

func progressBar(step, total int) string {
	const width = 14
	if step <= 0 {
		return strings.Repeat("░", width)
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
