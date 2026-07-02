package botapp

import (
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/i18n/bot"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

func (a *App) buildStockMessage() string {
	t := a.i18n.Bot
	list, err := results.ListProviders(a.cfg.ResultsDir)
	if err != nil || len(list) == 0 {
		return t.StockEmpty()
	}

	var b strings.Builder
	b.WriteString(t.StockHeader())
	total := 0
	for _, p := range list {
		emoji := bot.ProviderEmoji(p.Provider)
		b.WriteString(t.StockLine(emoji, p.Provider, p.Count))
		total += p.Count
	}
	b.WriteString(t.StockTotal(total))
	return b.String()
}
