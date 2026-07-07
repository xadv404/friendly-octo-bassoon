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
	a.tryLaunchHunt(chatID, userID)
}

func (a *App) handleStopScan(chatID int64) {
	t := a.i18n.Bot
	_, err := scanctl.Stop(a.cfg.ResultsDir)
	if err != nil {
		a.tg.Reply(chatID, t.ScanError(err.Error()))
		return
	}
	a.tg.Reply(chatID, t.ScanStopped(""))
}

func (a *App) startScan(chatID, userID int64) {
	a.tryLaunchHunt(chatID, userID)
}

func (a *App) stopScan(chatID int64) {
	a.handleStopScan(chatID)
}
