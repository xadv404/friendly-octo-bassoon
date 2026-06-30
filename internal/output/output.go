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
	fmt.Println(p.color(dim, "  Détection d'injections base de données — bug bounty"))
	fmt.Println()
}

func (p *Printer) Info(msg string)    { fmt.Println(p.color(blue, "[*]") + " " + msg) }
func (p *Printer) Success(msg string)  { fmt.Println(p.color(green, "[+]") + " " + msg) }
func (p *Printer) Warning(msg string)  { fmt.Println(p.color(yellow, "[!]") + " " + msg) }
func (p *Printer) Error(msg string)    { fmt.Println(p.color(red, "[-]") + " " + msg) }
func (p *Printer) Verbose(msg string)  { fmt.Println(p.color(dim, "[~]") + " " + msg) }

// Finding affiche une injection DB détectée.
func (p *Printer) Finding(f models.Finding) {
	fmt.Println()
	fmt.Println(p.color(red+bold, "  ═══ ACCÈS DB POTENTIEL ═══"))
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

// Summary affiche le résumé final.
func (p *Printer) Summary(result models.ScanResult) {
	fmt.Println()
	fmt.Println(p.color(bold, "─── Résumé ───"))
	fmt.Printf("  Paramètres testés : %d\n", result.TestedParams)
	fmt.Printf("  Payloads envoyés  : %d\n", result.TestedPayloads)
	fmt.Printf("  Injections DB     : %d\n", len(result.Findings))

	if len(result.Errors) > 0 {
		fmt.Println()
		p.Warning(fmt.Sprintf("%d erreur(s)", len(result.Errors)))
		for _, e := range result.Errors {
			fmt.Printf("    %s\n", e)
		}
	}

	fmt.Println()
	if len(result.Findings) > 0 {
		p.Success(fmt.Sprintf("%d injection(s) DB détectée(s)", len(result.Findings)))
	} else {
		p.Info("Aucune injection base de données détectée")
	}
}

func vulnLabel(v models.VulnType) string {
	labels := map[models.VulnType]string{
		models.SQLiError:   "SQL Injection (error-based)",
		models.SQLiBoolean: "SQL Injection (boolean-blind)",
		models.SQLiTime:    "SQL Injection (time-blind)",
		models.SQLiUnion:   "SQL Injection (union — extraction DB)",
		models.NoSQL:       "NoSQL Injection (MongoDB, etc.)",
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

// Extraction affiche une donnée extraite.
func (p *Printer) Extraction(d models.ExtractedData) {
	fmt.Println()
	fmt.Println(p.color(green+bold, "  ═══ DONNÉE EXTRAITE ═══"))
	fmt.Printf("  %s %s\n", p.color(bold, "Type:"), dataTypeLabel(d.DataType))
	fmt.Printf("  %s %s\n", p.color(bold, "Valeur:"), p.color(yellow, d.Value))
	fmt.Printf("  %s %s\n", p.color(bold, "Paramètre:"), d.Parameter)
	fmt.Printf("  %s %s\n", p.color(bold, "Méthode:"), d.Method)
	if d.DBMS != "" {
		fmt.Printf("  %s %s\n", p.color(bold, "DBMS:"), d.DBMS)
	}
	fmt.Printf("  %s %s\n", p.color(bold, "Payload:"), truncateURL(d.Payload, 80))
	fmt.Println()
}

// ExtractionSummary affiche le résumé des extractions.
func (p *Printer) ExtractionSummary(extractions []models.ExtractedData) {
	if len(extractions) == 0 {
		return
	}
	fmt.Println()
	fmt.Println(p.color(bold, "─── Données extraites ───"))
	for _, d := range extractions {
		fmt.Printf("  %s %s = %s\n",
			p.color(cyan, string(d.DataType)),
			p.color(dim, "["+d.Parameter+"]"),
			p.color(yellow, truncateURL(d.Value, 120)))
	}
	fmt.Println()
}

func dataTypeLabel(d models.DataType) string {
	labels := map[models.DataType]string{
		models.DataVersion:  "Version DB",
		models.DataDatabase: "Base de données",
		models.DataUser:     "Utilisateur DB",
		models.DataTables:   "Tables",
		models.DataColumns:  "Colonnes",
		models.DataDump:     "Dump NoSQL",
	}
	if l, ok := labels[d]; ok {
		return l
	}
	return string(d)
}

// PrintExtractMode affiche le mode extraction.
func (p *Printer) PrintExtractMode(mode string) {
	p.Info("Extraction : " + mode)
}

// PrintScanConfig affiche la configuration.
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
	p.Info("Injections DB : " + strings.Join(names, ", "))
	if waf {
		p.Info("WAF bypass : activé")
	}
}
