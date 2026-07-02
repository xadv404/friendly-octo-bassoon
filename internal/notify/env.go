package notify

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func loadNotifyEnv() {
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

func parseAllowedIDs(raw string) []int64 {
	var out []int64
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.ParseInt(part, 10, 64)
		if err == nil {
			out = append(out, id)
		}
	}
	return out
}
