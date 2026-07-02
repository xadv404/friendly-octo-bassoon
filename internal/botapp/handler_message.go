package botapp

import (
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func (a *App) handleMessage(msg *tgbotapi.Message) {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}

	t := a.i18n.Bot

	if text == "/myid" {
		a.tg.Reply(msg.Chat.ID, t.MyID(msg.From.ID))
		return
	}

	if !a.cfg.Authorized(msg.From.ID) {
		a.tg.Reply(msg.Chat.ID, t.AccessDenied(msg.From.ID))
		return
	}

	switch text {
	case "/start":
		a.pending.Clear(msg.From.ID)
		a.sendStart(msg.Chat.ID)
	default:
		if provider, ok := a.pending.Get(msg.From.ID); ok {
			a.handleQuantityInput(msg.Chat.ID, msg.From.ID, provider, text)
			return
		}
		a.tg.Reply(msg.Chat.ID, t.Hint())
	}
}

func (a *App) handleQuantityInput(chatID, userID int64, provider, text string) {
	t := a.i18n.Bot
	count, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || count <= 0 {
		a.tg.Reply(chatID, t.InvalidQty(provider))
		return
	}
	a.pending.Clear(userID)
	a.sendEmails(chatID, count, provider)
}
