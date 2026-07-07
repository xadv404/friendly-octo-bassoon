package notify

import (
	"sync"

	"github.com/sqli-hunter/sqli-hunter/internal/i18n"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// Sender envoie des alertes scan (Telegram whitelist).
type Sender interface {
	Enabled() bool
	Launch(title, detail string)
	DiscoverDone(kept, skipped, fetched int)
	ScanStarted(urlCount int, listFile string)
	Vuln(f models.Finding)
	DumpFail(f models.Finding, reason string)
	DumpOK(d models.ExtractedData, email string)
	Complete(title, detail string)
	Error(msg string)
	DiscoverProgress(phase string, step, total, kept, fetched, skipped int)
	ScanProgress(scanned, total, vulns, findings int)
	URLFound(url string)
}

// Noop désactive les notifications.
type Noop struct{}

func (Noop) Enabled() bool                       { return false }
func (Noop) Launch(string, string)               {}
func (Noop) DiscoverDone(int, int, int)          {}
func (Noop) ScanStarted(int, string)             {}
func (Noop) Vuln(models.Finding)                 {}
func (Noop) DumpFail(models.Finding, string)     {}
func (Noop) DumpOK(models.ExtractedData, string) {}
func (Noop) Complete(string, string)             {}
func (Noop) Error(string)                        {}
func (Noop) DiscoverProgress(string, int, int, int, int, int) {}
func (Noop) ScanProgress(int, int, int, int)                  {}
func (Noop) URLFound(string)                                   {}

var (
	defaultOnce sync.Once
	defaultSend Sender
)

// Default retourne le notifier Telegram (ou Noop si non configuré).
func Default() Sender {
	defaultOnce.Do(func() {
		defaultSend = newFromEnv()
	})
	return defaultSend
}

// ScanAborted met à jour le live board sans alerte de fin (arrêt manuel).
func ScanAborted(n Sender, scanned, total, vulns, findings int) {
	ts, ok := n.(*telegramSender)
	if !ok || !ts.Enabled() || ts.live == nil {
		return
	}
	ts.live.aborted(scanned, total, vulns, findings)
}

// StockSummary formate le stock emails (i18n).
func StockSummary(baseDir string) string {
	return i18n.Load().Alert.StockSummary(baseDir)
}
