package notify

import (
	"log"

	"github.com/sqli-hunter/sqli-hunter/internal/i18n"
	i18nalert "github.com/sqli-hunter/sqli-hunter/internal/i18n/alert"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/telegram"
)

type telegramSender struct {
	bc       *telegram.Broadcaster
	texts    i18nalert.Texts
	locale   string
	progress *progressGate
}

func newFromEnv() Sender {
	telegram.LoadEnvFiles()
	cfg, err := telegram.LoadConfig()
	if err != nil || cfg.Token == "" || len(cfg.Allowed) == 0 {
		return Noop{}
	}

	bc, err := telegram.NewBroadcaster(cfg.Token, cfg.AllowedChatIDs())
	if err != nil {
		log.Printf("notify: %v", err)
		return Noop{}
	}
	if bc == nil {
		return Noop{}
	}

	bundle := i18n.ForLocale(i18n.Locale(cfg.Locale))
	log.Printf("notify: alertes Telegram → %d ID(s) [%s]", len(cfg.Allowed), cfg.Locale)

	return &telegramSender{
		bc:       bc,
		texts:    bundle.Alert,
		locale:   cfg.Locale,
		progress: &progressGate{},
	}
}

func (t *telegramSender) Enabled() bool { return t != nil && t.bc != nil }

func (t *telegramSender) send(text string) {
	if t.Enabled() {
		t.bc.Broadcast(text)
	}
}

func (t *telegramSender) Launch(title, detail string) {
	t.send(t.texts.Launch(title, detail))
}

func (t *telegramSender) DiscoverDone(kept, skipped, fetched int) {
	t.send(t.texts.DiscoverDone(kept, skipped, fetched))
}

func (t *telegramSender) ScanStarted(urlCount int, listFile string) {
	t.send(t.texts.ScanStarted(urlCount, listFile))
}

func (t *telegramSender) Vuln(f models.Finding) {
	t.send(t.texts.Vuln(f))
}

func (t *telegramSender) DumpFail(f models.Finding, reason string) {
	t.send(t.texts.DumpFail(f, reason))
}

func (t *telegramSender) DumpOK(d models.ExtractedData, email string) {
	t.send(t.texts.DumpOK(d, email))
}

func (t *telegramSender) Complete(title, detail string) {
	t.send(t.texts.Complete(title, detail))
}

func (t *telegramSender) Error(msg string) {
	t.send(t.texts.Error(msg))
}

// DailyLaunch alerte démarrage daily.
func DailyLaunch(n Sender, limit, threads int, outputDir string) {
	ts, ok := n.(*telegramSender)
	if !ok || !ts.Enabled() {
		return
	}
	ts.Launch(ts.texts.TitleDailyLaunch, ts.texts.DailyLaunch(limit, threads, outputDir))
}

// DailyNoNew alerte fin daily sans nouvelles URLs.
func DailyNoNew(n Sender, baseDir string) {
	ts, ok := n.(*telegramSender)
	if !ok || !ts.Enabled() {
		return
	}
	ts.Complete(ts.texts.TitleDailyComplete, ts.texts.DailyNoNew(baseDir))
}

// ScanComplete alerte fin de scan massif.
func ScanComplete(n Sender, scanned, total, vulns, findings, newEmails int, stock string) {
	ts, ok := n.(*telegramSender)
	if !ok || !ts.Enabled() {
		return
	}
	detail := i18nalert.ScanCompleteDetail(ts.locale, scanned, total, vulns, findings, newEmails, stock)
	ts.Complete(ts.texts.TitleScanComplete, detail)
}
