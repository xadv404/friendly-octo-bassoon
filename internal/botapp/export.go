package botapp

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/i18n/bot"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

//go:embed assets/logo.png
var logoPNG []byte

func (a *App) welcomeCaption() string {
	return a.i18n.Bot.Welcome(a.buildStockMessage())
}

func (a *App) sendStart(chatID int64) {
	caption := a.welcomeCaption()
	kb := a.startKeyboard()

	if len(logoPNG) > 0 {
		err := a.tg.SendPhoto(chatID, tgbotapi.FileBytes{Name: "logo.png", Bytes: logoPNG}, caption, kb)
		if err != nil {
			log.Printf("photo send: %v", err)
			_ = a.tg.SendMessageText(chatID, caption, kb)
		}
		return
	}
	_ = a.tg.SendMessageText(chatID, caption, kb)
}

func (a *App) sendEmails(chatID int64, count int, providerQuery string) {
	t := a.i18n.Bot

	if count > a.cfg.MaxEmails {
		a.tg.Reply(chatID, t.MaxEmails(a.cfg.MaxEmails))
		return
	}

	taken, err := results.TakeEmailsForBot(a.cfg.ResultsDir, providerQuery, count)
	if err != nil {
		a.tg.Reply(chatID, t.TakeError(err.Error()))
		return
	}

	body := strings.Join(taken.Emails, "\n") + "\n"
	filename := fmt.Sprintf("%s_%d.txt", taken.Provider, len(taken.Emails))
	tmpPath := filepath.Join(os.TempDir(), filename)
	defer os.Remove(tmpPath)

	if err := os.WriteFile(tmpPath, []byte(body), 0644); err != nil {
		a.tg.Reply(chatID, t.WriteError())
		return
	}

	emoji := bot.ProviderEmoji(taken.Provider)
	caption := t.Delivery(emoji, taken.Provider, len(taken.Emails))
	if err := a.tg.SendDocument(chatID, tmpPath, caption); err != nil {
		a.tg.Reply(chatID, t.SendError(err.Error()))
		return
	}

	log.Printf("bot delivered %d %s to %d", len(taken.Emails), taken.Provider, chatID)
}
