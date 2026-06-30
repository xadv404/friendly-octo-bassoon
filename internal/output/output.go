package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

const (
	reset   = "\033[0m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	gray    = "\033[90m"
	white   = "\033[97m"
	bold    = "\033[1m"
	dim     = "\033[2m"
)

// Printer affiche la sortie CLI.
type Printer struct {
	noColor bool
	verbose bool
	mu      sync.Mutex
}

// New crée un printer.
func New(noColor, verbose bool) *Printer {
	if noColor || os.Getenv("NO_COLOR") != "" {
		noColor = true
	}
	return &Printer{noColor: noColor, verbose: verbose}
}

func (p *Printer) c(code, s string) string {
	if p.noColor {
		return s
	}
	return code + s + reset
}

func (p *Printer) lock()   { p.mu.Lock() }
func (p *Printer) unlock() { p.mu.Unlock() }

// Header affiche l'en-tête minimal.
func (p *Printer) Header(version string) {
	p.lock()
	defer p.unlock()
	fmt.Printf("%s sqli-hunter %s\n\n", p.c(gray, "»"), p.c(white+bold, version))
}

// KV affiche une ligne clé/valeur alignée.
func (p *Printer) KV(key, val string) {
	p.lock()
	defer p.unlock()
	fmt.Printf("  %-10s %s\n", p.c(gray, key), val)
}

// Rule affiche un séparateur discret.
func (p *Printer) Rule() {
	p.lock()
	defer p.unlock()
	fmt.Println(p.c(gray, strings.Repeat("─", 62)))
}

func (p *Printer) Info(msg string) {
	p.lock()
	defer p.unlock()
	fmt.Printf("  %s %s\n", p.c(blue, "·"), msg)
}

func (p *Printer) Success(msg string) {
	p.lock()
	defer p.unlock()
	fmt.Printf("  %s %s\n", p.c(green, "✓"), msg)
}

func (p *Printer) Warning(msg string) {
	p.lock()
	defer p.unlock()
	fmt.Printf("  %s %s\n", p.c(yellow, "!"), msg)
}

func (p *Printer) Error(msg string) {
	p.lock()
	defer p.unlock()
	fmt.Fprintf(os.Stderr, "  %s %s\n", p.c(red, "✗"), msg)
}

func (p *Printer) Verbose(msg string) {
	if !p.verbose {
		return
	}
	p.lock()
	defer p.unlock()
	fmt.Printf("  %s %s\n", p.c(dim, "~"), p.c(gray, msg))
}

// ScanConfig affiche la configuration du scan.
func (p *Printer) ScanConfig(mode models.ScanMode, categories []models.VulnCategory, waf bool) {
	modeLabel := "fast"
	if mode == models.ScanFull {
		modeLabel = "full"
	}
	names := make([]string, len(categories))
	for i, c := range categories {
		names[i] = string(c)
	}
	p.KV("mode", modeLabel+" · "+strings.Join(names, ", "))
	if waf {
		p.KV("waf", "bypass on")
	}
}

// ScanProgress affiche la progression sur une liste d'URLs.
func (p *Printer) ScanProgress(index, total int, targetURL string, findings int, elapsed time.Duration) {
	p.lock()
	defer p.unlock()

	width := len(fmt.Sprintf("%d", total))
	status := p.c(gray, "ok")
	if findings > 0 {
		status = p.c(red+bold, fmt.Sprintf("vuln(%d)", findings))
	}

	fmt.Printf("  %s %s %4s  %s\n",
		p.c(gray, fmt.Sprintf("[%*d/%d]", width, index, total)),
		status,
		formatDuration(elapsed),
		truncate(targetURL, 72),
	)
}

// Finding affiche une vulnérabilité détectée.
func (p *Printer) Finding(f models.Finding) {
	p.lock()
	defer p.unlock()

	conf := confidenceStyle(p, f.Confidence)
	fmt.Printf("\n  %s  %s  %s  %s\n",
		p.c(red+bold, "VULN"),
		p.c(cyan, string(f.VulnType)),
		p.c(white, f.Parameter),
		conf,
	)
	fmt.Printf("  %s\n", p.c(gray, truncate(f.URL, 100)))

	if p.verbose {
		if f.DBMS != "" {
			fmt.Printf("  %s %s\n", p.c(gray, "dbms"), f.DBMS)
		}
		fmt.Printf("  %s %s\n", p.c(gray, "payload"), truncate(f.Payload, 90))
		if f.Evidence != "" {
			fmt.Printf("  %s %s\n", p.c(gray, "proof"), truncate(f.Evidence, 90))
		}
	}
}

// Extraction affiche une donnée extraite (compact).
func (p *Printer) Extraction(d models.ExtractedData) {
	p.lock()
	defer p.unlock()
	fmt.Printf("  %s %s %s\n",
		p.c(gray, "→"),
		p.c(green, dataTypeLabel(d.DataType)),
		p.c(white, truncate(d.Value, 100)),
	)
}

// TargetSummary résumé par cible en mode verbose.
func (p *Printer) TargetSummary(url string, findings, extractions int, elapsed time.Duration) {
	if !p.verbose || findings == 0 {
		return
	}
	p.lock()
	defer p.unlock()
	fmt.Printf("  %s %d finding(s), %d extract(s) in %s\n",
		p.c(gray, "└"), findings, extractions, formatDuration(elapsed))
}

// Summary affiche le résumé final.
func (p *Printer) Summary(scanned, vulnerable, findings, extractions int, elapsed time.Duration) {
	p.Rule()
	p.lock()
	defer p.unlock()

	fmt.Printf("  %s %d scanned",
		p.c(gray, "done"),
		scanned,
	)
	if vulnerable > 0 {
		fmt.Printf(" · %s %d vulnerable",
			p.c(red, ""), vulnerable)
	}
	fmt.Printf(" · %d finding(s)", findings)
	if extractions > 0 {
		fmt.Printf(" · %d extract(s)", extractions)
	}
	fmt.Printf(" · %s\n", formatDuration(elapsed))
	fmt.Println()
}

// SingleSummary résumé mode URL unique.
func (p *Printer) SingleSummary(result models.ScanResult) {
	p.Rule()
	p.lock()
	defer p.unlock()

	fmt.Printf("  %s %d param(s) · %d payload(s) · %d finding(s)",
		p.c(gray, "done"),
		result.TestedParams,
		result.TestedPayloads,
		len(result.Findings),
	)
	if len(result.Extractions) > 0 {
		fmt.Printf(" · %d extract(s)", len(result.Extractions))
	}
	fmt.Println()
	fmt.Println()

	if len(result.Findings) > 0 {
		fmt.Printf("  %s %d injection(s) détectée(s)\n", p.c(green, "✓"), len(result.Findings))
	} else {
		fmt.Printf("  %s aucune injection détectée\n", p.c(gray, "·"))
	}
	if len(result.Errors) > 0 && p.verbose {
		for _, e := range result.Errors {
			fmt.Printf("  %s %s\n", p.c(yellow, "!"), e)
		}
	}
	fmt.Println()
}

func confidenceStyle(p *Printer, c models.Confidence) string {
	switch c {
	case models.Confirmed:
		return p.c(red+bold, string(c))
	case models.High:
		return p.c(red, string(c))
	case models.Medium:
		return p.c(yellow, string(c))
	default:
		return p.c(gray, string(c))
	}
}

func dataTypeLabel(d models.DataType) string {
	labels := map[models.DataType]string{
		models.DataVersion:  "version",
		models.DataDatabase: "database",
		models.DataUser:     "user",
		models.DataTables:   "tables",
		models.DataColumns:  "columns",
		models.DataDump:     "dump",
	}
	if l, ok := labels[d]; ok {
		return l
	}
	return string(d)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
}
