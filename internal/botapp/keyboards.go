package botapp

import (
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/i18n/bot"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

func (a *App) startKeyboard() tgbotapi.InlineKeyboardMarkup {
	t := a.i18n.Bot
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.BtnExtract(), "menu:extract"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.BtnDorks(), "menu:dorks"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(t.BtnScanStart(), "scan:hunt"),
		),
	)
}

func (a *App) providerKeyboard(list []results.ProviderInfo) tgbotapi.InlineKeyboardMarkup {
	t := a.i18n.Bot
	var rows [][]tgbotapi.InlineKeyboardButton
	var row []tgbotapi.InlineKeyboardButton
	for i, p := range list {
		emoji := bot.ProviderEmoji(p.Provider)
		label := t.ProviderLabel(emoji, p.Provider, p.Count)
		row = append(row, tgbotapi.NewInlineKeyboardButtonData(label, "prov:"+p.Provider))
		if len(row) == 2 || i == len(list)-1 {
			rows = append(rows, row)
			row = nil
		}
	}
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData(t.BtnBack(), "menu:start"),
	))
	return tgbotapi.InlineKeyboardMarkup{InlineKeyboard: rows}
}
