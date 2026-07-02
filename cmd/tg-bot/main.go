package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

//go:embed assets/logo.png
var logoPNG []byte

type config struct {
	token      string
	resultsDir string
	maxEmails  int
	allowed    map[int64]bool
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	bot, err := tgbotapi.NewBotAPI(cfg.token)
	if err != nil {
		log.Fatal(err)
	}
	bot.Debug = os.Getenv("TELEGRAM_DEBUG") == "1"

	if err := results.CompactAllEmails(cfg.resultsDir); err != nil {
		log.Printf("compact emails: %v", err)
	}

	if len(cfg.allowed) == 0 {
		log.Println("ATTENTION: TELEGRAM_ALLOWED_IDS vide — seul /myid accessible jusqu'à config")
	} else {
		log.Printf("bot @%s — whitelist: %d ID(s)", bot.Self.UserName, len(cfg.allowed))
	}
	log.Printf("emails: %s", results.EmailsDir(cfg.resultsDir))

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.CallbackQuery != nil {
			handleCallback(bot, cfg, update.CallbackQuery)
			continue
		}
		if update.Message == nil {
			continue
		}
		handleMessage(bot, cfg, update.Message)
	}
}

func handleMessage(bot *tgbotapi.BotAPI, cfg config, msg *tgbotapi.Message) {
	text := strings.TrimSpace(msg.Text)
	if text == "" {
		return
	}

	if text == "/myid" {
		reply(bot, msg.Chat.ID, myIDText(msg.From.ID))
		return
	}

	if !cfg.authorized(msg.From.ID) {
		reply(bot, msg.Chat.ID, accessDeniedText(msg.From.ID))
		return
	}

	switch {
	case text == "/start":
		sendStart(bot, cfg, msg.Chat.ID)
	default:
		reply(bot, msg.Chat.ID, hintText())
	}
}

func startKeyboard() tgbotapi.InlineKeyboardMarkup {
	return tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnExtract(), "menu:extract"),
		),
	)
}

func sendStart(bot *tgbotapi.BotAPI, cfg config, chatID int64) {
	caption := welcomeCaption(cfg)
	kb := startKeyboard()

	if len(logoPNG) > 0 {
		photo := tgbotapi.NewPhoto(chatID, tgbotapi.FileBytes{Name: "logo.png", Bytes: logoPNG})
		photo.Caption = fmt.Sprintf("🇨🇭 *%s*", botName)
		photo.ParseMode = "Markdown"
		_, _ = bot.Send(photo)
	}
	sendStartText(bot, chatID, caption, kb)
}

func sendStartText(bot *tgbotapi.BotAPI, chatID int64, caption string, kb tgbotapi.InlineKeyboardMarkup) {
	msg := tgbotapi.NewMessage(chatID, caption)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = kb
	if _, err := bot.Send(msg); err != nil {
		msg.ParseMode = ""
		_, _ = bot.Send(msg)
	}
}

func handleCallback(bot *tgbotapi.BotAPI, cfg config, cq *tgbotapi.CallbackQuery) {
	if cq.Message == nil {
		return
	}
	chatID := cq.Message.Chat.ID
	data := cq.Data

	if !cfg.authorized(cq.From.ID) {
		answerCallback(bot, cq.ID, callbackDenied())
		return
	}

	switch {
	case data == "menu:start":
		editStart(bot, cfg, chatID, cq.Message.MessageID)
		answerCallback(bot, cq.ID, "")
	case data == "menu:extract":
		list, err := results.ListProviders(cfg.resultsDir)
		if err != nil || len(list) == 0 {
			answerCallback(bot, cq.ID, callbackEmpty())
			reply(bot, chatID, emptyStockText())
			return
		}
		var rows [][]tgbotapi.InlineKeyboardButton
		var row []tgbotapi.InlineKeyboardButton
		for i, p := range list {
			label := providerButtonLabel(p.Provider, p.Count)
			row = append(row, tgbotapi.NewInlineKeyboardButtonData(label, "prov:"+p.Provider))
			if len(row) == 2 || i == len(list)-1 {
				rows = append(rows, row)
				row = nil
			}
		}
		rows = append(rows, tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData(btnBack(), "menu:start"),
		))
		edit := tgbotapi.NewEditMessageText(chatID, cq.Message.MessageID, extractMenuText())
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &tgbotapi.InlineKeyboardMarkup{InlineKeyboard: rows}
		_, _ = bot.Send(edit)
		answerCallback(bot, cq.ID, "")
	case strings.HasPrefix(data, "prov:"):
		provider := strings.TrimPrefix(data, "prov:")
		qtyKeyboard := quantityKeyboard(provider)
		edit := tgbotapi.NewEditMessageText(chatID, cq.Message.MessageID, quantityText(provider))
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &qtyKeyboard
		_, _ = bot.Send(edit)
		answerCallback(bot, cq.ID, "")
	case strings.HasPrefix(data, "qty:"):
		rest := strings.TrimPrefix(data, "qty:")
		i := strings.LastIndex(rest, ":")
		if i <= 0 || i >= len(rest)-1 {
			answerCallback(bot, cq.ID, callbackError())
			return
		}
		provider := rest[:i]
		count, err := strconv.Atoi(rest[i+1:])
		if err != nil || count <= 0 {
			answerCallback(bot, cq.ID, callbackBadQty())
			return
		}
		answerCallback(bot, cq.ID, callbackSending())
		sendEmails(bot, cfg, chatID, count, provider)
	default:
		answerCallback(bot, cq.ID, "")
	}
}

func editStart(bot *tgbotapi.BotAPI, cfg config, chatID int64, messageID int) {
	text := stockMessage(cfg)
	kb := startKeyboard()
	edit := tgbotapi.NewEditMessageText(chatID, messageID, fmt.Sprintf("🇨🇭 *%s*\n_Stock emails .ch_\n\n%s", botName, text))
	edit.ParseMode = "Markdown"
	edit.ReplyMarkup = &kb
	_, _ = bot.Send(edit)
}

func quantityKeyboard(provider string) tgbotapi.InlineKeyboardMarkup {
	counts := []int{10, 50, 100, 500, 1000}
	var rows [][]tgbotapi.InlineKeyboardButton
	var row []tgbotapi.InlineKeyboardButton
	for i, n := range counts {
		row = append(row, tgbotapi.NewInlineKeyboardButtonData(qtyButtonLabel(n), fmt.Sprintf("qty:%s:%d", provider, n)))
		if len(row) == 3 || i == len(counts)-1 {
			rows = append(rows, row)
			row = nil
		}
	}
	rows = append(rows, tgbotapi.NewInlineKeyboardRow(
		tgbotapi.NewInlineKeyboardButtonData(btnProviders(), "menu:extract"),
	))
	return tgbotapi.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func sendEmails(bot *tgbotapi.BotAPI, cfg config, chatID int64, count int, providerQuery string) {
	if count > cfg.maxEmails {
		reply(bot, chatID, fmt.Sprintf("⚠️ Max *%d* emails par requête.", cfg.maxEmails))
		return
	}

	taken, err := results.TakeEmailsForBot(cfg.resultsDir, providerQuery, count)
	if err != nil {
		reply(bot, chatID, "❌ "+err.Error())
		return
	}

	body := strings.Join(taken.Emails, "\n") + "\n"
	filename := fmt.Sprintf("%s_%d.txt", taken.Provider, len(taken.Emails))
	tmpPath := filepath.Join(os.TempDir(), filename)
	defer os.Remove(tmpPath)

	if err := os.WriteFile(tmpPath, []byte(body), 0644); err != nil {
		reply(bot, chatID, "❌ Erreur écriture fichier.")
		return
	}

	doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(tmpPath))
	doc.Caption = deliveryCaption(taken.Provider, len(taken.Emails))
	doc.ParseMode = "Markdown"

	if _, err := bot.Send(doc); err != nil {
		reply(bot, chatID, "❌ Envoi échoué: "+err.Error())
		return
	}

	log.Printf("bot delivered %d %s to %d", len(taken.Emails), taken.Provider, chatID)
}

func answerCallback(bot *tgbotapi.BotAPI, id, text string) {
	cb := tgbotapi.NewCallback(id, text)
	_, _ = bot.Request(cb)
}

func reply(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	if _, err := bot.Send(msg); err != nil {
		msg.ParseMode = ""
		_, _ = bot.Send(msg)
	}
}
