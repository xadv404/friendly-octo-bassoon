package discover

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExportDorksFile écrit les requêtes Google (une par ligne) pour recherche manuelle.
func ExportDorksFile(path, domain string, subs bool, set DorkSet) (int, error) {
	dorks := BuildDorks(set, domain, subs)
	if len(dorks) == 0 {
		return 0, fmt.Errorf("aucun dork pour %q", domain)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return 0, err
	}
	var b strings.Builder
	for _, d := range dorks {
		d = strings.TrimSpace(d)
		d = strings.ReplaceAll(d, "\r", "")
		d = strings.ReplaceAll(d, "\n", " ")
		if d == "" {
			continue
		}
		b.WriteString(d)
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return 0, err
	}
	return len(dorks), nil
}

// DefaultDorksPath chemin par défaut du fichier dorks exporté.
func DefaultDorksPath(baseDir string) string {
	if baseDir == "" {
		baseDir = "results"
	}
	return filepath.Join(baseDir, "dorks_ch.txt")
}
