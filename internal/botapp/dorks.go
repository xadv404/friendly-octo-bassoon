package botapp

import (
	"github.com/sqli-hunter/sqli-hunter/internal/discover"
)

func (a *App) sendDorks(chatID int64) {
	t := a.i18n.Bot
	path := discover.DefaultDorksPath(a.cfg.ResultsDir)
	n, err := discover.ExportDorksFile(path, "ch", true, discover.DorkSetBig)
	if err != nil {
		a.tg.Reply(chatID, t.DorksError(err.Error()))
		return
	}
	caption := t.DorksSent(n)
	if err := a.tg.SendDocument(chatID, path, caption); err != nil {
		a.tg.Reply(chatID, t.DorksError(err.Error()))
	}
}
