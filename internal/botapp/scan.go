package botapp

import (
	"errors"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/scanctl"
)

func (a *App) handleScanCommand(chatID int64, text string) {
	t := a.i18n.Bot
	parts := strings.Fields(text)
	if len(parts) == 1 {
		a.tg.Reply(chatID, t.ScanUsage())
		return
	}

	var extra []string
	for i := 1; i < len(parts); i++ {
		if parts[i] == "--cycle-weeks" && i+1 < len(parts) {
			extra = append(extra, "--cycle-weeks", parts[i+1])
			i++
			continue
		}
	}

	out, err := scanctl.Start(a.cfg.ResultsDir, "hunt", extra...)
	switch {
	case errors.Is(err, scanctl.ErrAlreadyRunning):
		a.tg.Reply(chatID, t.ScanAlreadyRunning("hunt"))
	case err != nil:
		a.tg.Reply(chatID, t.ScanError(err.Error()))
	default:
		_, pid, log := scanctl.ParseStarted(out)
		a.tg.Reply(chatID, t.ScanStarted("hunt", pid, log))
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

func (a *App) startScan(chatID int64) {
	a.handleScanCommand(chatID, "/scan hunt")
}

func (a *App) stopScan(chatID int64) {
	a.handleStopScan(chatID)
}
