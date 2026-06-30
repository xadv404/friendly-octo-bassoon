package output

import (
	"fmt"
	"os"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

const (
	reset  = "\033[0m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
	bold   = "\033[1m"
	dim    = "\033[2m"
)

// Printer affiche les résultats en CLI colorée.
type Printer struct {
	noColor bool
}

// NewPrinter crée un printer CLI.
func NewPrinter(noColor bool) *Printer {
	if noColor || os.Getenv("NO_COLOR") != "" {
		noColor = true
	}
	return &Printer{noColor: noColor}
}

func (p *Printer) color(code, s string) string {
	if p.noColor {
		return s
	}
	return code + s + reset
}

// Banner affiche la bannière de démarrage.
func (p *Printer) Banner() {
	fmt.Println(p.color(cyan+bold, `
  ╔═╗┌─┐╦  ┬┬ ┬  ╦ ╦┬ ┬┌┐┌┌┬┐┌─┐┬─┐
  ╚═╗│ ││  ││││  ╠═╣└┬┘│││ │ ├┤ ├┬┘
  ╚═╝└─┘┴─┘┴└┴┘  ╩ ╩ ┴ ┘└┘ ┴ └─┘┴└─
`))
	fmt.Println(p.color(dim, "  Scanner rapide de vulnérabilités web — bug bounty"))
	fmt.Println()
}

// Info affiche un message informatif.
func (p *Printer) Info(msg string) {
	fmt.Println(p.color(blue, "[*]") + " " + msg)
}

// Success affiche un message de succès.
func (p *Printer) Success(msg string) {
	fmt.Println(p.color(green, "[+]") + " " + msg)
}

// Warning affiche un avertissement.
func (p *Printer) Warning(msg string) {
	fmt.Println(p.color(yellow, "[!]") + " " + msg)
}

// Error affiche une erreur.
func (p *Printer) Error(msg string) {
	fmt.Println(p.color(red, "[-]") + " " + msg)
}

// Verbose affiche un message de debug.
func (p *Printer) Verbose(msg string) {
	fmt.Println(p.color(dim, "[~]") + " " + msg)
}

// Finding affiche une vulnérabilité détectée en temps réel.
func (p *Printer) Finding(f models.Finding) {
	fmt.Println()
	fmt.Println(p.color(red+bold, "  ═══ VULNÉRABILITÉ DÉTECTÉE ═══"))
	fmt.Printf("  %s %s\n", p.color(bold, "Paramètre:"), f.Parameter)
	fmt.Printf("  %s %s\n", p.color(bold, "Type:"), vulnLabel(f.VulnType))
	fmt.Printf("  %s %s\n", p.color(bold, "Confiance:"), confidenceColor(p, f.Confidence))
	fmt.Printf("  %s %s\n", p.color(bold, "Payload:"), f.Payload)
	if f.DBMS != "" {
		fmt.Printf("  %s %s\n", p.color(bold, "DBMS:"), f.DBMS)
	}
	fmt.Printf("  %s %s\n", p.color(bold, "Preuve:"), f.Evidence)
	if f.ResponseTimeMs > 0 {
		fmt.Printf("  %s %.0fms\n", p.color(bold, "Temps:"), f.ResponseTimeMs)
	}
	fmt.Printf("  %s %d\n", p.color(bold, "HTTP:"), f.StatusCode)
	fmt.Printf("  %s %s\n", p.color(bold, "URL:"), truncateURL(f.URL, 100))
	fmt.Println()
}

// Summary affiche le résumé final du scan.
func (p *Printer) Summary(result models.ScanResult) {
	fmt.Println()
	fmt.Println(p.color(bold, "─── Résumé ───"))
	fmt.Printf("  Paramètres testés : %d\n", result.TestedParams)
	fmt.Printf("  Payloads envoyés  : %d\n", result.TestedPayloads)
	fmt.Printf("  Findings          : %d\n", len(result.Findings))

	if len(result.Errors) > 0 {
		fmt.Println()
		p.Warning(fmt.Sprintf("%d erreur(s) durant le scan", len(result.Errors)))
		for _, e := range result.Errors {
			fmt.Printf("    %s\n", e)
		}
	}

	fmt.Println()
	if len(result.Findings) > 0 {
		p.Success(fmt.Sprintf("%d vulnérabilité(s) potentielle(s) détectée(s)", len(result.Findings)))
	} else {
		p.Info("Aucune vulnérabilité détectée avec le profil configuré")
	}
}

func vulnLabel(v models.VulnType) string {
	labels := map[models.VulnType]string{
		models.SQLiError:    "SQL Injection (error-based)",
		models.SQLiBoolean:  "SQL Injection (boolean-blind)",
		models.SQLiTime:     "SQL Injection (time-blind)",
		models.SQLiUnion:    "SQL Injection (union-based)",
		models.XSS:          "XSS (réfléchi)",
		models.SSTI:         "SSTI (Server-Side Template Injection)",
		models.OpenRedirect: "Open Redirect",
		models.LFI:          "LFI / Path Traversal",
		models.SSRF:         "SSRF",
		models.IDOR:         "IDOR (Broken Access Control)",
	}
	if l, ok := labels[v]; ok {
		return l
	}
	return string(v)
}

func confidenceColor(p *Printer, c models.Confidence) string {
	switch c {
	case models.Confirmed:
		return p.color(red+bold, string(c))
	case models.High:
		return p.color(red, string(c))
	case models.Medium:
		return p.color(yellow, string(c))
	default:
		return p.color(dim, string(c))
	}
}

func truncateURL(u string, n int) string {
	if len(u) <= n {
		return u
	}
	return u[:n] + "..."
}

// PrintScanConfig affiche la configuration du scan.
func (p *Printer) PrintScanConfig(mode models.ScanMode, categories []models.VulnCategory, waf bool) {
	modeLabel := "rapide"
	if mode == models.ScanFull {
		modeLabel = "complet"
	}
	p.Info("Mode : " + modeLabel)

	names := make([]string, len(categories))
	for i, c := range categories {
		names[i] = string(c)
	}
	p.Info("Vulnérabilités : " + strings.Join(names, ", "))
	if waf {
		p.Info("WAF bypass : activé")
	}
}
