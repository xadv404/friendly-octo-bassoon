package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/discover"
)

func init() {
	loadSqliHunterEnv()
	discover.ReloadProxyPool()
}

func loadSqliHunterEnv() {
	for _, path := range []string{
		os.Getenv("SQLI_HUNTER_ENV"),
		"sqli-hunter.env",
		"config/sqli-hunter.env",
	} {
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
