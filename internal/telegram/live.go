package telegram

import (
	"log"
	"strings"
	"sync"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// LiveEditor maintient un message par chat et le met à jour via EditMessageText.
// Si l'édition échoue, un nouveau message est envoyé et l'ID est remplacé.
type LiveEditor struct {
	bot     *tgbotapi.BotAPI
	chatIDs []int64
	mu      sync.Mutex
	msgID   map[int64]int
}

// NewLiveEditor crée un éditeur live à partir d'un Broadcaster.
func NewLiveEditor(bc *Broadcaster) *LiveEditor {
	if bc == nil || bc.bot == nil || len(bc.chatIDs) == 0 {
		return nil
	}
	return &LiveEditor{
		bot:     bc.bot,
		chatIDs: append([]int64(nil), bc.chatIDs...),
		msgID:   make(map[int64]int),
	}
}

// Set met à jour le message live pour tous les chats whitelistés.
func (e *LiveEditor) Set(text string) {
	if e == nil || strings.TrimSpace(text) == "" {
		return
	}
	for _, chatID := range e.chatIDs {
		e.setOne(chatID, text)
	}
}

func (e *LiveEditor) setOne(chatID int64, text string) {
	e.mu.Lock()
	mid := e.msgID[chatID]
	e.mu.Unlock()

	if mid == 0 {
		e.sendNew(chatID, text)
		return
	}

	edit := tgbotapi.NewEditMessageText(chatID, mid, text)
	edit.DisableWebPagePreview = true
	if _, err := e.bot.Send(edit); err != nil {
		if isEditUnchanged(err) {
			return
		}
		log.Printf("telegram: edit %d msg %d: %v", chatID, mid, err)
		e.sendNew(chatID, text)
	}
}

func isEditUnchanged(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "message is not modified") ||
		strings.Contains(msg, "MESSAGE_NOT_MODIFIED")
}

func (e *LiveEditor) sendNew(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.DisableWebPagePreview = true
	sent, err := e.bot.Send(msg)
	if err != nil {
		log.Printf("telegram: send %d: %v", chatID, err)
		return
	}
	e.mu.Lock()
	e.msgID[chatID] = sent.MessageID
	e.mu.Unlock()
}
