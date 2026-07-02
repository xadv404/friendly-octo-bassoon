package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func loadEnvFiles() {
	candidates := []string{
		os.Getenv("TG_BOT_ENV"),
		"tg-bot.env",
		"config/tg-bot.env",
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if err := loadDotEnv(path); err == nil {
			return
		}
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

func loadConfig() (config, error) {
	loadEnvFiles()

	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if token == "" {
		return config{}, fmt.Errorf("TELEGRAM_BOT_TOKEN requis (tg-bot.env ou variable d'environnement)")
	}

	resultsDir := strings.TrimSpace(os.Getenv("RESULTS_DIR"))
	if resultsDir == "" {
		resultsDir = "results"
	}

	maxEmails := 10000
	if v := strings.TrimSpace(os.Getenv("TELEGRAM_MAX_EMAILS")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return config{}, fmt.Errorf("TELEGRAM_MAX_EMAILS invalide: %s", v)
		}
		maxEmails = n
	}

	allowed := parseAllowedIDs(os.Getenv("TELEGRAM_ALLOWED_IDS"))

	return config{
		token:      token,
		resultsDir: resultsDir,
		maxEmails:  maxEmails,
		allowed:    allowed,
	}, nil
}

func parseAllowedIDs(raw string) map[int64]bool {
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

func (c config) authorized(userID int64) bool {
	if len(c.allowed) == 0 {
		return false
	}
	return c.allowed[userID]
}
