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
	Phase string // discover, fresh-pass, scan, done, stopped, no-new, error

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
	Paused     bool
	Slow       bool
}

// RenderBoard formate le message live complet (rétrocompat tests).
func RenderBoard(loc string, st BoardState) string {
	if st.Phase == "scan" || st.Phase == "done" || st.Phase == "stopped" || st.ScanDone {
		return RenderScanBoard(loc, st)
	}
	return RenderDiscoverBoard(loc, st)
}

// RenderDiscoverBoard — stats discover (legacy).
func RenderDiscoverBoard(loc string, st BoardState) string {
	if st.Error != "" {
		return "❌ " + st.Error
	}
	if st.DiscoverDone || st.Phase == "scan" || st.Phase == "done" {
		if st.DorkTotal > 0 {
			return fmt.Sprintf("🔍 %d/%d · 📌 %d URLs", max(st.DorkStep, st.DorkTotal), st.DorkTotal, st.Kept)
		}
		return fmt.Sprintf("🔍 📌 %d URLs", st.Kept)
	}
	if st.DorkTotal > 0 {
		line := fmt.Sprintf("🔍 %s %d/%d", progressBar(st.DorkStep, st.DorkTotal), st.DorkStep, st.DorkTotal)
		if st.Kept > 0 || st.Fetched > 0 {
			line += fmt.Sprintf(" · 📌 %d", st.Kept)
		}
		return line
	}
	return "🔍 …"
}

// RenderScanBoard — stats scan uniquement (1 message live édité).
func RenderScanBoard(loc string, st BoardState) string {
	if st.Error != "" {
		return "❌ " + st.Error
	}
	l := labelsForScan(loc)

	switch st.Phase {
	case "stopped":
		body := l.prefixStopped + "\n" + formatScanStats(l, st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK, st.NewEmails, false)
		if st.Paused {
			return "⏸ en pause\n" + body
		}
		return body
	case "done", "no-new":
		body := "✅ " + l.done + "\n" + formatScanStats(l, st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK, st.NewEmails, true)
		if compact := compactStock(st.Stock); compact != "" {
			body += "\n📦 " + l.stock + " : " + compact
		}
		return body
	}

	var b strings.Builder
	b.WriteString("🛡 ")
	if st.Paused {
		b.WriteString("⏸ en pause\n")
	} else if st.Slow {
		b.WriteString("⏳ URL lente…\n")
	}
	if st.ScanTotal > 0 {
		b.WriteString(progressBar(st.Scanned, st.ScanTotal))
		b.WriteByte('\n')
	}
	b.WriteString(formatScanStats(l, st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK, 0, false))
	return b.String()
}

type scanBoardLabels struct {
	prefixStopped string
	done          string
	stock         string
	scanned       string
	vulnerable    string
	findings      string
	dumps         string
	emails        string
}

func labelsForScan(loc string) scanBoardLabels {
	if loc == "en" {
		return scanBoardLabels{
			prefixStopped: "⏹ Stopped",
			done:          "Done",
			stock:         "stock",
			scanned:       "scanned",
			vulnerable:    "vulnerable",
			findings:      "findings",
			dumps:         "dumps",
			emails:        "new emails",
		}
	}
	return scanBoardLabels{
		prefixStopped: "⏹ Arrêté",
		done:          "Terminé",
		stock:         "stock",
		scanned:       "scanné",
		vulnerable:    "vulnérable",
		findings:      "findings",
		dumps:         "dumps",
		emails:        "emails",
	}
}

func formatScanStats(l scanBoardLabels, scanned, total, vulns, findings, dumps, newEmails int, showEmails bool) string {
	var lines []string
	if total > 0 {
		lines = append(lines, fmt.Sprintf("📊 %s : %d/%d", l.scanned, scanned, total))
	} else if scanned > 0 {
		lines = append(lines, fmt.Sprintf("📊 %s : %d", l.scanned, scanned))
	}
	lines = append(lines,
		fmt.Sprintf("🔴 %s : %d", l.vulnerable, vulns),
		fmt.Sprintf("🔎 %s : %d", l.findings, findings),
		fmt.Sprintf("💾 %s : %d", l.dumps, dumps),
	)
	if showEmails && newEmails > 0 {
		lines = append(lines, fmt.Sprintf("📬 %s : %d", l.emails, newEmails))
	}
	return strings.Join(lines, "\n")
}

func scanStatsLine(scanned, total, vulns, findings, dumps int, prefix string) string {
	_ = prefix
	l := labelsForScan("fr")
	return formatScanStats(l, scanned, total, vulns, findings, dumps, 0, false)
}

func scanStatsCore(scanned, total, vulns, findings, dumps int) string {
	l := labelsForScan("fr")
	return formatScanStats(l, scanned, total, vulns, findings, dumps, 0, false)
}

func compactStock(stock string) string {
	stock = strings.TrimSpace(stock)
	if stock == "" {
		return ""
	}
	lines := strings.Split(stock, "\n")
	if len(lines) == 0 {
		return ""
	}
	// "stock emails:\n• gmail.com — 12" → "gmail 12 · bluewin 5"
	var parts []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") || strings.Contains(line, "vide") || strings.Contains(line, "empty") {
			continue
		}
		line = strings.TrimPrefix(line, "• ")
		line = strings.TrimPrefix(line, "- ")
		line = strings.ReplaceAll(line, " — ", " ")
		parts = append(parts, line)
	}
	return strings.Join(parts, " · ")
}

func progressBar(step, total int) string {
	const width = 10
	if step <= 0 {
		return strings.Repeat("░", width)
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
