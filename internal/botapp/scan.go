package botapp

import (
	"errors"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/scanctl"
)

func (a *App) handleScanCommand(chatID int64, text string) {
	t := a.i18n.Bot
	parts := strings.Fields(text)
	tier := "weekly"
	if len(parts) >= 2 {
		tier = parts[1]
	}
	if len(parts) == 1 {
		a.tg.Reply(chatID, t.ScanUsage())
		return
	}

	out, err := scanctl.Start(a.cfg.ResultsDir, tier)
	switch {
	case errors.Is(err, scanctl.ErrAlreadyRunning):
		a.tg.Reply(chatID, t.ScanAlreadyRunning(tier))
	case err != nil:
		a.tg.Reply(chatID, t.ScanError(err.Error()))
	default:
		gotTier, pid, log := scanctl.ParseStarted(out)
		if gotTier == "" {
			gotTier = tier
		}
		a.tg.Reply(chatID, t.ScanStarted(gotTier, pid, log))
	}
}

func (a *App) handleStopScan(chatID int64) {
	t := a.i18n.Bot
	out, err := scanctl.Stop(a.cfg.ResultsDir)
	if err != nil {
		a.tg.Reply(chatID, t.ScanError(err.Error()))
		return
	}
	if scanctl.HasIdleOutput(out) {
		a.tg.Reply(chatID, t.ScanStopIdle())
		return
	}
	a.tg.Reply(chatID, t.ScanStopped(scanctl.FormatLines(out)))
}

func (a *App) startScanTier(chatID int64, tier string) {
	a.handleScanCommand(chatID, "/scan "+tier)
}

func (a *App) stopScan(chatID int64) {
	a.handleStopScan(chatID)
}
