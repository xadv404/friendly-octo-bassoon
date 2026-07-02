package telegram

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Config configuration Telegram partagée (bot export + alertes scan).
type Config struct {
	Token      string
	Locale     string
	ResultsDir string
	MaxEmails  int
	Allowed    map[int64]bool
}

// LoadEnvFiles charge tg-bot.env et sqli-hunter.env.
func LoadEnvFiles() {
	for _, path := range []string{
		os.Getenv("TG_BOT_ENV"),
		"tg-bot.env",
		"config/tg-bot.env",
		os.Getenv("SQLI_HUNTER_ENV"),
		"sqli-hunter.env",
		"config/sqli-hunter.env",
	} {
		if path == "" {
			continue
		}
		_ = loadDotEnv(path)
	}
}

func loadDotEnv(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if key != "" && os.Getenv(key) == "" {
			_ = os.Setenv(key, val)
		}
	}
	return sc.Err()
}

// LoadConfig charge la config depuis l'environnement.
func LoadConfig() (Config, error) {
	LoadEnvFiles()
	cfg := Config{
		Token:      strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")),
		Locale:     localeFromEnv(),
		ResultsDir: strings.TrimSpace(os.Getenv("RESULTS_DIR")),
		MaxEmails:  10000,
		Allowed:    ParseAllowedIDs(os.Getenv("TELEGRAM_ALLOWED_IDS")),
	}
	if cfg.ResultsDir == "" {
		cfg.ResultsDir = "results"
	}
	if v := strings.TrimSpace(os.Getenv("TELEGRAM_MAX_EMAILS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return Config{}, errInvalidMaxEmails(v)
		}
		cfg.MaxEmails = n
	}
	return cfg, nil
}

func localeFromEnv() string {
	for _, key := range []string{"TELEGRAM_LOCALE", "APP_LOCALE"} {
		if v := strings.ToLower(strings.TrimSpace(os.Getenv(key))); v != "" {
			if v == "en" || v == "eng" || v == "english" {
				return "en"
			}
		}
	}
	return "fr"
}

// ParseAllowedIDs parse TELEGRAM_ALLOWED_IDS.
func ParseAllowedIDs(raw string) map[int64]bool {
	out := make(map[int64]bool)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err == nil {
			out[id] = true
		}
	}
	return out
}

// Authorized vérifie la whitelist.
func (c Config) Authorized(userID int64) bool {
	if len(c.Allowed) == 0 {
		return false
	}
	return c.Allowed[userID]
}

// AllowedChatIDs liste les IDs whitelistés.
func (c Config) AllowedChatIDs() []int64 {
	out := make([]int64, 0, len(c.Allowed))
	for id := range c.Allowed {
		out = append(out, id)
	}
	return out
}

func errInvalidMaxEmails(v string) error {
	return &configError{msg: "TELEGRAM_MAX_EMAILS invalide: " + v}
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }

const maxQueue = 512

// Broadcaster envoie des messages aux IDs whitelistés (file async).
type Broadcaster struct {
	bot     *tgbotapi.BotAPI
	chatIDs []int64
	queue   chan string
	once    sync.Once
}

// NewBroadcaster crée un broadcaster ou nil si token/ids manquants.
func NewBroadcaster(token string, chatIDs []int64) (*Broadcaster, error) {
	if token == "" || len(chatIDs) == 0 {
		return nil, nil
	}
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		return nil, err
	}
	b := &Broadcaster{
		bot:     bot,
		chatIDs: chatIDs,
		queue:   make(chan string, maxQueue),
	}
	b.once.Do(func() {
		go b.worker()
	})
	return b, nil
}

func (b *Broadcaster) worker() {
	for text := range b.queue {
		for _, chatID := range b.chatIDs {
			msg := tgbotapi.NewMessage(chatID, text)
			msg.DisableWebPagePreview = true
			if _, err := b.bot.Send(msg); err != nil {
				log.Printf("telegram: send %d: %v", chatID, err)
			}
		}
	}
}

// Broadcast enqueue un message pour tous les IDs whitelistés.
func (b *Broadcaster) Broadcast(text string) {
	if b == nil || strings.TrimSpace(text) == "" {
		return
	}
	select {
	case b.queue <- text:
	default:
		log.Printf("telegram: queue pleine, message ignoré")
	}
}

// BotAPI retourne l'API Telegram sous-jacente (bot interactif).
func (b *Broadcaster) BotAPI() *tgbotapi.BotAPI {
	if b == nil {
		return nil
	}
	return b.bot
}
