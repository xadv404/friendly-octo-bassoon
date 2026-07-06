package botapp

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

func (a *App) sendStatus(chatID int64) {
	dir := a.cfg.ResultsDir
	st, ok := results.LoadRunStatus(dir)
	scopeN := latestScopeCount(dir)
	scannedN := results.CountLines(filepath.Join(dir, "scanned_urls.txt"))

	t := a.i18n.Bot
	if !ok {
		a.tg.Reply(chatID, t.Status(scopeN, scannedN, results.RunStatus{Phase: "idle"}, ""))
		return
	}

	age := ""
	if !st.UpdatedAt.IsZero() {
		age = fmt.Sprintf("%s", time.Since(st.UpdatedAt).Round(time.Second))
	}
	a.tg.Reply(chatID, t.Status(scopeN, scannedN, st, age))
}

func latestScopeCount(dir string) int {
	best := 0
	for _, name := range []string{"scope_monthly.txt", "scope_weekly.txt", "scope_big.txt"} {
		if n := results.CountLines(filepath.Join(dir, name)); n > best {
			best = n
		}
	}
	return best
}
