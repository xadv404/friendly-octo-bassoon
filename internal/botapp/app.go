package botapp

import (
	"log"
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/i18n"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
	"github.com/sqli-hunter/sqli-hunter/internal/telegram"
)

// App bot Telegram d'export emails.
type App struct {
	cfg     telegram.Config
	i18n    *i18n.Bundle
	tg      *telegram.Client
	pending      *pendingQty
	pendingScope *pendingScope
}

// Run démarre le bot (bloquant).
func Run() error {
	telegram.LoadEnvFiles()
	cfg, err := telegram.LoadConfig()
	if err != nil {
		return err
	}
	if cfg.Token == "" {
		return errMissingToken()
	}

	bc, err := telegram.NewBroadcaster(cfg.Token, cfg.AllowedChatIDs())
	if err != nil {
		return err
	}
	api := bc.BotAPI()
	if api == nil {
		return errMissingToken()
	}
	api.Debug = os.Getenv("TELEGRAM_DEBUG") == "1"

	if err := results.CompactAllEmails(cfg.ResultsDir); err != nil {
		log.Printf("compact emails: %v", err)
	}

	if len(cfg.Allowed) == 0 {
		log.Println("ATTENTION: TELEGRAM_ALLOWED_IDS vide — seul /myid accessible")
	} else {
		log.Printf("bot @%s — whitelist: %d ID(s) [%s]", api.Self.UserName, len(cfg.Allowed), cfg.Locale)
	}
	log.Printf("emails: %s", results.EmailsDir(cfg.ResultsDir))

	app := &App{
		cfg:     cfg,
		i18n:    i18n.ForLocale(i18n.Locale(cfg.Locale)),
		tg:      telegram.NewClient(api),
		pending:      newPendingQty(),
		pendingScope: newPendingScope(),
	}

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30
	for update := range api.GetUpdatesChan(u) {
		if update.CallbackQuery != nil {
			app.handleCallback(update.CallbackQuery)
			continue
		}
		if update.Message != nil {
			app.handleMessage(update.Message)
		}
	}
	return nil
}

type missingTokenError struct{}

func errMissingToken() error { return missingTokenError{} }

func (missingTokenError) Error() string {
	return "TELEGRAM_BOT_TOKEN requis (tg-bot.env ou variable d'environnement)"
}
