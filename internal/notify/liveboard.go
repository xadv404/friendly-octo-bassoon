package notify

import (
	"sync"
	"time"

	i18nalert "github.com/sqli-hunter/sqli-hunter/internal/i18n/alert"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/scanctl"
	"github.com/sqli-hunter/sqli-hunter/internal/telegram"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

const liveFlushInterval = 6 * time.Second

type liveBoard struct {
	editor     *telegram.LiveEditor
	locale     string
	texts      i18nalert.Texts
	resultsDir string
	mode       string // discover | scan

	mu            sync.Mutex
	state         i18nalert.BoardState
	lastFlush     time.Time
	lastProgress  time.Time
	dirty         bool
	stopCh    chan struct{}
	once      sync.Once
}

func newLiveBoard(bc *telegram.Broadcaster, locale, resultsDir string, texts i18nalert.Texts) *liveBoard {
	ed := telegram.NewLiveEditor(bc)
	if ed == nil {
		return nil
	}
	lb := &liveBoard{
		editor:     ed,
		locale:     locale,
		texts:      texts,
		resultsDir: resultsDir,
		stopCh:     make(chan struct{}),
	}
	lb.once.Do(func() {
		go lb.flusher()
	})
	return lb
}

func (lb *liveBoard) flusher() {
	tick := time.NewTicker(liveFlushInterval)
	defer tick.Stop()
	for {
		select {
		case <-lb.stopCh:
			return
		case <-tick.C:
			lb.mu.Lock()
			if lb.dirty {
				lb.flushLocked(false)
			}
			lb.mu.Unlock()
		}
	}
}

func (lb *liveBoard) markDirty(immediate bool) {
	lb.dirty = true
	if immediate || time.Since(lb.lastFlush) >= liveFlushInterval {
		lb.flushLocked(immediate)
	}
}

func (lb *liveBoard) flushLocked(_ bool) {
	if !lb.dirty {
		return
	}
	lb.state.Paused = scanctl.IsPaused(lb.resultsDir)
	lb.state.Slow = lb.state.Phase == "scan" && !lb.state.Paused &&
		!lb.lastProgress.IsZero() && time.Since(lb.lastProgress) > 45*time.Second
	var text string
	if lb.mode == "scan" {
		text = i18nalert.RenderScanBoard(lb.locale, lb.state)
	} else {
		text = i18nalert.RenderDiscoverBoard(lb.locale, lb.state)
	}
	var kb *tgbotapi.InlineKeyboardMarkup
	clearKB := false
	if lb.mode == "scan" {
		switch lb.state.Phase {
		case "scan":
			k := telegram.ScanControlKeyboard(scanctl.IsPaused(lb.resultsDir), lb.locale)
			kb = &k
		case "done", "stopped", "no-new":
			clearKB = true
		}
	}
	lb.editor.Set(text, kb, clearKB)
	lb.lastFlush = time.Now()
	lb.dirty = false
}

func (lb *liveBoard) setLaunch(_, _ string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.mode = "discover"
	lb.state = i18nalert.BoardState{Phase: "discover"}
	lb.markDirty(true)
}

func (lb *liveBoard) resetBoard() {
	lb.setLaunch("", "")
}

func (lb *liveBoard) updateDiscover(phase string, step, total, kept, fetched, skipped int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.Phase = phase
	lb.state.DorkStep = step
	lb.state.DorkTotal = total
	lb.state.Kept = kept
	lb.state.Fetched = fetched
	lb.state.Skipped = skipped
	if phase == "fresh-pass" {
		lb.state.DiscoverLabel = ""
	} else {
		lb.state.DiscoverLabel = ""
	}
	lb.markDirty(false)
}

func (lb *liveBoard) addURL(url string) {
	_ = url
}

func (lb *liveBoard) discoverDone(kept, skipped, fetched int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.Kept = kept
	lb.state.Skipped = skipped
	lb.state.Fetched = fetched
	lb.state.DiscoverDone = true
	if lb.state.DorkTotal > 0 {
		lb.state.DorkStep = lb.state.DorkTotal
	}
	lb.markDirty(true)
}

func (lb *liveBoard) scanStarted(urlCount int, _ string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.mode = "scan"
	lb.state = i18nalert.BoardState{
		Phase:     "scan",
		ScanTotal: urlCount,
	}
	lb.lastProgress = time.Now()
	lb.markDirty(true)
}

func (lb *liveBoard) updateScan(scanned, total, vulns, findings int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.Phase = "scan"
	lb.state.Scanned = scanned
	if total > 0 {
		lb.state.ScanTotal = total
	}
	lb.state.Vulns = vulns
	lb.state.Findings = findings
	lb.lastProgress = time.Now()
	lb.markDirty(false)
}

func (lb *liveBoard) addVuln(_ models.Finding) {}

func (lb *liveBoard) addDumpFail(_ models.Finding, _ string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.DumpFails++
	lb.markDirty(false)
}

func (lb *liveBoard) addDumpOK(_ models.ExtractedData, email string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.DumpsOK++
	if email != "" {
		for _, e := range lb.state.EmailsList {
			if e == email {
				return
			}
		}
	}
	lb.markDirty(false)
}

func (lb *liveBoard) addEmail(email string) {
	_ = email
}

func (lb *liveBoard) complete(title, detail, stock string, scanned, total, vulns, findings, newEmails int, done bool) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.Phase = "done"
	if done && total == 0 && scanned == 0 {
		lb.state.Phase = "no-new"
	}
	lb.state.Detail = detail
	lb.state.Stock = stock
	lb.state.Scanned = scanned
	lb.state.ScanTotal = total
	lb.state.Vulns = vulns
	lb.state.Findings = findings
	lb.state.NewEmails = newEmails
	lb.state.ScanDone = true
	lb.state.DiscoverDone = true
	lb.markDirty(true)
}

func (lb *liveBoard) setError(msg string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.Error = msg
	if lb.state.Phase == "" {
		lb.state.Phase = "error"
	}
	lb.markDirty(true)
}

func (lb *liveBoard) aborted(scanned, total, vulns, findings int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.state.Phase = "stopped"
	lb.state.Scanned = scanned
	lb.state.ScanTotal = total
	lb.state.Vulns = vulns
	lb.state.Findings = findings
	lb.markDirty(true)
}
