package botapp

import (
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/i18n/bot"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
	"github.com/sqli-hunter/sqli-hunter/internal/scanctl"
	"github.com/sqli-hunter/sqli-hunter/internal/telegram"
)

func (a *App) handleCallback(cq *tgbotapi.CallbackQuery) {
	if cq.Message == nil {
		return
	}
	t := a.i18n.Bot
	chatID := cq.Message.Chat.ID
	data := cq.Data

	if !a.cfg.Authorized(cq.From.ID) {
		a.tg.AnswerCallback(cq.ID, t.CallbackDenied())
		return
	}

	switch {
	case data == "menu:start":
		a.editStart(chatID, cq.Message)
		a.tg.AnswerCallback(cq.ID, "")
	case data == "menu:extract":
		list, err := results.ListProviders(a.cfg.ResultsDir)
		if err != nil || len(list) == 0 {
			a.tg.AnswerCallback(cq.ID, t.CallbackEmpty())
			a.tg.Reply(chatID, t.StockEmpty())
			return
		}
		a.tg.AnswerCallback(cq.ID, "")
		a.tg.EditMenu(chatID, cq.Message.MessageID, t.ExtractMenu(), a.providerKeyboard(list), isPhotoMessage(cq.Message))
	case strings.HasPrefix(data, "scan:"):
		action := strings.TrimPrefix(data, "scan:")
		switch action {
		case "hunt", "weekly", "monthly":
			a.startScan(chatID, cq.From.ID)
			a.tg.AnswerCallback(cq.ID, "")
		case "pause":
			paused, err := scanctl.TogglePause(a.cfg.ResultsDir)
			if err != nil {
				a.tg.AnswerCallback(cq.ID, t.ScanError(err.Error()))
				return
			}
			if paused {
				a.tg.AnswerCallback(cq.ID, "⏸")
			} else {
				a.tg.AnswerCallback(cq.ID, "▶️")
			}
			kb := telegram.ScanControlKeyboard(paused, a.cfg.Locale)
			a.tg.EditReplyMarkup(chatID, cq.Message.MessageID, kb)
		case "stop":
			a.stopScan(chatID)
			a.tg.AnswerCallback(cq.ID, "")
		}
	case strings.HasPrefix(data, "prov:"):
		provider := strings.TrimPrefix(data, "prov:")
		a.pending.Set(cq.From.ID, provider)
		emoji := bot.ProviderEmoji(provider)
		a.tg.Reply(chatID, t.QuantityAsk(emoji, provider))
		a.tg.AnswerCallback(cq.ID, "")
	default:
		a.tg.AnswerCallback(cq.ID, "")
	}
}

func (a *App) editStart(chatID int64, msg *tgbotapi.Message) {
	a.tg.EditMenu(chatID, msg.MessageID, a.welcomeCaption(), a.startKeyboard(), isPhotoMessage(msg))
}

func isPhotoMessage(msg *tgbotapi.Message) bool {
	return msg != nil && len(msg.Photo) > 0
}
