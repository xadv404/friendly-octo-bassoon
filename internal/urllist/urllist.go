package urllist

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Load lit un fichier d'URLs (une par ligne, # pour commentaires).
func Load(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ouverture liste : %w", err)
	}
	defer f.Close()

	var urls []string
	seen := make(map[string]bool)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if _, err := url.ParseRequestURI(raw); err != nil {
			return nil, fmt.Errorf("ligne %d : URL invalide %q : %w", lineNo, raw, err)
		}
		if seen[raw] {
			continue
		}
		seen[raw] = true
		urls = append(urls, raw)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("lecture liste : %w", err)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("liste vide : %s", path)
	}
	return urls, nil
}
