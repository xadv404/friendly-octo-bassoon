package urllist

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Count compte les URLs valides sans tout charger en mémoire.
func Count(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("ouverture liste : %w", err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	n := 0
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		if _, err := url.ParseRequestURI(raw); err != nil {
			continue
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		n++
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return n, nil
}

// Stream envoie les URLs sur un channel (fermé à la fin).
func Stream(path string, out chan<- string) error {
	defer close(out)

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ouverture liste : %w", err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
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
			return fmt.Errorf("ligne %d : URL invalide %q : %w", lineNo, raw, err)
		}
		if _, ok := seen[raw]; ok {
			continue
		}
		seen[raw] = struct{}{}
		out <- raw
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("lecture liste : %w", err)
	}
	return nil
}
