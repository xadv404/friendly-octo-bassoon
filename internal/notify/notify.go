package notify

import (
	"strings"
	"sync"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// Sender envoie des alertes scan (Telegram whitelist).
type Sender interface {
	Enabled() bool
	Launch(title, detail string)
	DiscoverDone(kept, skipped, fetched int)
	Vuln(f models.Finding)
	DumpFail(f models.Finding, reason string)
	DumpOK(d models.ExtractedData, email string)
	Complete(title, detail string)
	Error(msg string)
}

// Noop désactive les notifications.
type Noop struct{}

func (Noop) Enabled() bool                                      { return false }
func (Noop) Launch(string, string)                              {}
func (Noop) DiscoverDone(int, int, int)                         {}
func (Noop) Vuln(models.Finding)                                {}
func (Noop) DumpFail(models.Finding, string)                    {}
func (Noop) DumpOK(models.ExtractedData, string)                {}
func (Noop) Complete(string, string)                            {}
func (Noop) Error(string)                                       {}

var (
	defaultOnce sync.Once
	defaultSend Sender
)

// Default retourne le notifier Telegram (ou Noop si non configuré).
func Default() Sender {
	defaultOnce.Do(func() {
		defaultSend = newTelegramFromEnv()
	})
	return defaultSend
}

func truncURL(u string, n int) string {
	u = strings.TrimSpace(u)
	if len(u) <= n {
		return u
	}
	return u[:n-1] + "…"
}

func formatFinding(f models.Finding) string {
	return strings.Join([]string{
		"URL: " + truncURL(f.URL, 120),
		"param: " + f.Parameter,
		"type: " + string(f.VulnType),
		"dbms: " + f.DBMS,
	}, "\n")
}

func formatDumpDetail(d models.ExtractedData, email string) string {
	lines := []string{
		"URL: " + truncURL(d.FindingURL, 120),
		"param: " + d.Parameter,
		"type: " + string(d.VulnType),
	}
	if d.DBMS != "" {
		lines = append(lines, "dbms: "+d.DBMS)
	}
	if email != "" {
		lines = append(lines, "email: "+email)
	}
	if d.PII != nil {
		if d.PII.Prenom != "" || d.PII.Nom != "" {
			lines = append(lines, "nom: "+strings.TrimSpace(d.PII.Prenom+" "+d.PII.Nom))
		}
		if d.PII.Telephone != "" {
			lines = append(lines, "tel: "+d.PII.Telephone)
		}
	}
	return strings.Join(lines, "\n")
}

// StockSummary formate le stock emails pour Telegram.
func StockSummary(baseDir string) string {
	list, err := results.ListProviders(baseDir)
	if err != nil || len(list) == 0 {
		return "stock emails: vide"
	}
	var b strings.Builder
	b.WriteString("stock emails:\n")
	for _, p := range list {
		b.WriteString("• ")
		b.WriteString(p.Provider)
		b.WriteString(" — ")
		b.WriteString(itoa(p.Count))
		b.WriteString("\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}
