package botapp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/scanctl"
	"github.com/sqli-hunter/sqli-hunter/internal/urllist"
)

const huntScopeFile = "scope_hunt.txt"

func (a *App) scopePath() string {
	return filepath.Join(a.cfg.ResultsDir, huntScopeFile)
}

func (a *App) scopeURLCount() (int, error) {
	return urllist.Count(a.scopePath())
}

func (a *App) tryLaunchHunt(chatID, userID int64) {
	t := a.i18n.Bot
	if running, _, err := scanctl.Running(a.cfg.ResultsDir); err == nil && running {
		a.tg.Reply(chatID, t.ScanAlreadyRunning("hunt"))
		return
	}

	count, err := a.scopeURLCount()
	if err != nil || count == 0 {
		a.pending.Clear(userID)
		a.pendingScope.Set(userID)
		a.tg.Reply(chatID, t.ScanAskScope())
		return
	}

	a.pendingScope.Clear(userID)
	a.launchHunt(chatID)
}

func (a *App) launchHunt(chatID int64) {
	t := a.i18n.Bot
	_, err := scanctl.Start(a.cfg.ResultsDir, "hunt")
	switch {
	case errors.Is(err, scanctl.ErrAlreadyRunning):
		a.tg.Reply(chatID, t.ScanAlreadyRunning("hunt"))
	case err != nil:
		a.tg.Reply(chatID, t.ScanError(err.Error()))
	}
}

func (a *App) handleDocument(msg *tgbotapi.Message) {
	if msg.From == nil || msg.Document == nil {
		return
	}
	t := a.i18n.Bot
	chatID := msg.Chat.ID
	userID := msg.From.ID

	name := strings.ToLower(msg.Document.FileName)
	if !strings.HasSuffix(name, ".txt") {
		a.tg.Reply(chatID, t.ScanScopeBadFile())
		return
	}

	tmpPath := filepath.Join(os.TempDir(), "scope_upload_"+msg.Document.FileID+".txt")
	defer os.Remove(tmpPath)

	if err := a.tg.DownloadDocument(msg.Document.FileID, tmpPath); err != nil {
		a.tg.Reply(chatID, t.ScanScopeError(err.Error()))
		return
	}

	if _, err := urllist.Load(tmpPath); err != nil {
		a.tg.Reply(chatID, t.ScanScopeError(err.Error()))
		return
	}

	dest := a.scopePath()
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		a.tg.Reply(chatID, t.ScanScopeError(err.Error()))
		return
	}
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		a.tg.Reply(chatID, t.ScanScopeError(err.Error()))
		return
	}
	if err := os.WriteFile(dest, data, 0644); err != nil {
		a.tg.Reply(chatID, t.ScanScopeError(err.Error()))
		return
	}

	a.pendingScope.Clear(userID)
	a.launchHunt(chatID)
}
