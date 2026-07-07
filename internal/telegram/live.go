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
		if isEditNotFound(err) {
			log.Printf("telegram: edit %d msg %d: %v — nouveau message", chatID, mid, err)
			e.sendNew(chatID, text)
		} else {
			log.Printf("telegram: edit %d msg %d ignoré: %v", chatID, mid, err)
		}
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

func isEditNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "message to edit not found") ||
		strings.Contains(msg, "MESSAGE_ID_INVALID") ||
		strings.Contains(msg, "message can't be edited")
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

// DeleteAll supprime les messages live et réinitialise les IDs (transition discover → scan).
func (e *LiveEditor) DeleteAll() {
	if e == nil {
		return
	}
	e.mu.Lock()
	ids := make(map[int64]int, len(e.msgID))
	for chatID, mid := range e.msgID {
		ids[chatID] = mid
	}
	e.msgID = make(map[int64]int)
	e.mu.Unlock()

	for chatID, mid := range ids {
		if mid <= 0 {
			continue
		}
		if _, err := e.bot.Request(tgbotapi.NewDeleteMessage(chatID, mid)); err != nil {
			log.Printf("telegram: delete %d msg %d: %v", chatID, mid, err)
		}
	}
}
