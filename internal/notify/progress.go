package notify

import (
	"sync"
	"time"
)

const progressMinInterval = 2 * time.Minute

type progressGate struct {
	mu           sync.Mutex
	lastDiscover time.Time
	lastScan     time.Time
}

func (g *progressGate) allowDiscover(step, total, kept int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	milestone := kept > 0 && step > 0 && step%25 == 0
	if total > 0 && step == total {
		milestone = true
	}
	if milestone || now.Sub(g.lastDiscover) >= progressMinInterval {
		g.lastDiscover = now
		return true
	}
	return false
}

func (g *progressGate) allowScan(scanned int) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if scanned > 0 && scanned%50 == 0 || now.Sub(g.lastScan) >= progressMinInterval {
		g.lastScan = now
		return true
	}
	return false
}

func (t *telegramSender) DiscoverProgress(phase string, step, total, kept, fetched, skipped int) {
	if !t.Enabled() || t.progress == nil {
		return
	}
	if !t.progress.allowDiscover(step, total, kept) {
		return
	}
	t.send(t.texts.DiscoverProgress(phase, step, total, kept, fetched, skipped))
}

func (t *telegramSender) ScanProgress(scanned, total, vulns, findings int) {
	if !t.Enabled() || t.progress == nil {
		return
	}
	if !t.progress.allowScan(scanned) {
		return
	}
	t.send(t.texts.ScanProgress(scanned, total, vulns, findings))
}
