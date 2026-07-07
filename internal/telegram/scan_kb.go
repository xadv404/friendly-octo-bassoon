package telegram

import tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

// ScanControlKeyboard boutons pause/stop sur le message de progression live.
func ScanControlKeyboard(paused bool, loc string) tgbotapi.InlineKeyboardMarkup {
	pause, stop := "⏸ Pause", "⏹ Stop"
	if paused {
		pause = "▶️ Reprendre"
	}
	if loc == "en" {
		if paused {
			pause = "▶️ Resume"
		} else {
			pause = "⏸ Pause"
		}
		stop = "⏹ Stop"
	}
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(pause, "scan:pause"),
			tgbotapi.NewInlineKeyboardButtonData(stop, "scan:stop"),
		),
	)
}
