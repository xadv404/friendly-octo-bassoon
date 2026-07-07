package botapp

import (
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/scanctl"
)

func (a *App) handleScanCommand(chatID, userID int64, text string) {
	t := a.i18n.Bot
	parts := strings.Fields(text)
	if len(parts) == 1 {
		a.tg.Reply(chatID, t.ScanUsage())
		return
	}

	if running, _, err := scanctl.Running(a.cfg.ResultsDir); err == nil && running {
		a.tg.Reply(chatID, t.ScanAlreadyRunning("hunt"))
		return
	}

	a.pending.Clear(userID)
	a.pendingScope.Set(userID)
	a.tg.Reply(chatID, t.ScanAskScope())
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
	a.tg.Reply(chatID, t.ScanStopped(""))
}

func (a *App) startScan(chatID, userID int64) {
	a.handleScanCommand(chatID, userID, "/scan hunt")
}

func (a *App) stopScan(chatID int64) {
	a.handleStopScan(chatID)
}
