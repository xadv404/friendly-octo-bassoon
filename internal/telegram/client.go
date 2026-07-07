package telegram

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Client helpers d'envoi pour le bot interactif.
type Client struct {
	api *tgbotapi.BotAPI
}

// NewClient crée un client Telegram.
func NewClient(api *tgbotapi.BotAPI) *Client {
	return &Client{api: api}
}

// Reply envoie un message texte Markdown.
func (c *Client) Reply(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	if _, err := c.api.Send(msg); err != nil {
		msg.ParseMode = ""
		_, _ = c.api.Send(msg)
	}
}

// AnswerCallback répond à un callback inline.
func (c *Client) AnswerCallback(id, text string) {
	cb := tgbotapi.NewCallback(id, text)
	_, _ = c.api.Request(cb)
}

// SendPhoto envoie une photo avec caption et clavier.
func (c *Client) SendPhoto(chatID int64, photo tgbotapi.RequestFileData, caption string, kb tgbotapi.InlineKeyboardMarkup) error {
	p := tgbotapi.NewPhoto(chatID, photo)
	p.Caption = caption
	p.ParseMode = "Markdown"
	p.ReplyMarkup = kb
	_, err := c.api.Send(p)
	return err
}

// SendMessageText envoie un message avec clavier inline.
func (c *Client) SendMessageText(chatID int64, text string, kb tgbotapi.InlineKeyboardMarkup) error {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = kb
	_, err := c.api.Send(msg)
	if err != nil {
		msg.ParseMode = ""
		_, err = c.api.Send(msg)
	}
	return err
}

// EditMenu édite un message (caption ou texte).
func (c *Client) EditMenu(chatID int64, messageID int, text string, kb tgbotapi.InlineKeyboardMarkup, photo bool) {
	if photo {
		edit := tgbotapi.NewEditMessageCaption(chatID, messageID, text)
		edit.ParseMode = "Markdown"
		edit.ReplyMarkup = &kb
		if _, err := c.api.Send(edit); err != nil {
			edit.ParseMode = ""
			_, _ = c.api.Send(edit)
		}
		return
	}
	edit := tgbotapi.NewEditMessageText(chatID, messageID, text)
	edit.ParseMode = "Markdown"
	edit.ReplyMarkup = &kb
	if _, err := c.api.Send(edit); err != nil {
		edit.ParseMode = ""
		_, _ = c.api.Send(edit)
	}
}

// EditReplyMarkup met à jour les boutons inline d'un message.
func (c *Client) EditReplyMarkup(chatID int64, messageID int, kb tgbotapi.InlineKeyboardMarkup) {
	edit := tgbotapi.NewEditMessageReplyMarkup(chatID, messageID, kb)
	if _, err := c.api.Send(edit); err != nil {
		log.Printf("telegram: edit markup %d msg %d: %v", chatID, messageID, err)
	}
}

// SendDocument envoie un fichier.
func (c *Client) SendDocument(chatID int64, path, caption string) error {
	doc := tgbotapi.NewDocument(chatID, tgbotapi.FilePath(path))
	doc.Caption = caption
	doc.ParseMode = "Markdown"
	_, err := c.api.Send(doc)
	return err
}

// DownloadDocument télécharge un document Telegram vers dest.
func (c *Client) DownloadDocument(fileID, dest string) error {
	file, err := c.api.GetFile(tgbotapi.FileConfig{FileID: fileID})
	if err != nil {
		return err
	}
	resp, err := http.Get(file.Link(c.api.Token))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("téléchargement HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}
