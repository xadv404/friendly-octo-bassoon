package bot

import "github.com/sqli-hunter/sqli-hunter/internal/results"

// Texts messages UI du bot d'export emails.
type Texts struct {
	BotName string

	Welcome       func(stock string) string
	StockEmpty    func() string
	StockHeader   func() string
	StockLine     func(emoji, provider string, count int) string
	StockTotal    func(total int) string

	ExtractMenu   func() string
	QuantityAsk   func(emoji, provider string) string
	InvalidQty    func(provider string) string
	Hint          func() string
	Delivery      func(emoji, provider string, count int) string
	MaxEmails     func(max int) string
	WriteError    func() string
	SendError     func(err string) string
	TakeError     func(err string) string

	AccessDenied  func(userID int64) string
	MyID          func(userID int64) string

	BtnExtract    func() string
	BtnBack       func() string
	ProviderLabel func(emoji, provider string, count int) string

	CallbackDenied func() string
	CallbackEmpty  func() string

	Status func(scopeN, scannedN int, st results.RunStatus, updatedAgo string) string
}

// For retourne les textes bot pour une locale (fr, en).
func For(loc string) Texts {
	if loc == "en" {
		return en
	}
	return fr
}
