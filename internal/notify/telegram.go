package notify

import (
	"log"
	"os"
	"strings"
	"sync"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

const maxQueue = 512

type Telegram struct {
	bot     *tgbotapi.BotAPI
	chatIDs []int64
	queue   chan string
	once    sync.Once
}

func newTelegramFromEnv() Sender {
	loadNotifyEnv()
	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	ids := parseAllowedIDs(os.Getenv("TELEGRAM_ALLOWED_IDS"))
	if token == "" || len(ids) == 0 {
		return Noop{}
	}

	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		log.Printf("notify: telegram init: %v", err)
		return Noop{}
	}

	t := &Telegram{
		bot:     bot,
		chatIDs: ids,
		queue:   make(chan string, maxQueue),
	}
	t.once.Do(func() {
		go t.worker()
		log.Printf("notify: alertes Telegram → %d ID(s) whitelist", len(ids))
	})
	return t
}

func (t *Telegram) Enabled() bool { return t != nil && t.bot != nil && len(t.chatIDs) > 0 }

func (t *Telegram) enqueue(text string) {
	if !t.Enabled() || strings.TrimSpace(text) == "" {
		return
	}
	select {
	case t.queue <- text:
	default:
		log.Printf("notify: file pleine, message ignoré")
	}
}

func (t *Telegram) worker() {
	for text := range t.queue {
		for _, chatID := range t.chatIDs {
			msg := tgbotapi.NewMessage(chatID, text)
			msg.DisableWebPagePreview = true
			if _, err := t.bot.Send(msg); err != nil {
				log.Printf("notify: envoi %d: %v", chatID, err)
			}
		}
	}
}

func (t *Telegram) Launch(title, detail string) {
	t.enqueue("🚀 " + title + "\n" + detail)
}

func (t *Telegram) DiscoverDone(kept, skipped, fetched int) {
	t.enqueue(strings.Join([]string{
		"🔎 Discover terminé",
		"URLs gardées: " + itoa(kept),
		"ignorées: " + itoa(skipped),
		"lues: " + itoa(fetched),
	}, "\n"))
}

func (t *Telegram) Vuln(f models.Finding) {
	t.enqueue("🔴 VULN " + string(f.VulnType) + "\n" + formatFinding(f))
}

func (t *Telegram) DumpFail(f models.Finding, reason string) {
	t.enqueue("⚠️ Dump impossible\n" + formatFinding(f) + "\nraison: " + reason)
}

func (t *Telegram) DumpOK(d models.ExtractedData, email string) {
	t.enqueue("✅ Dump OK\n" + formatDumpDetail(d, email))
}

func (t *Telegram) Complete(title, detail string) {
	t.enqueue("🏁 " + title + "\n" + detail)
}

func (t *Telegram) Error(msg string) {
	t.enqueue("❌ " + msg)
}
