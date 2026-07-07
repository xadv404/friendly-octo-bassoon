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
	written := 0
	for _, d := range dorks {
		d = CleanDorkForExport(d)
		if d == "" {
			continue
		}
		b.WriteString(d)
		b.WriteByte('\n')
		written++
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return 0, err
	}
	return written, nil
}

// CleanDorkForExport retire les exclusions auto (-inurl:wp-content…) pour usage manuel Google.
func CleanDorkForExport(d string) string {
	d = strings.TrimSpace(d)
	d = strings.ReplaceAll(d, "\r", "")
	d = strings.ReplaceAll(d, "\n", " ")
	if i := strings.Index(d, " -inurl:wp-content"); i > 0 {
		d = strings.TrimSpace(d[:i])
	}
	return d
}

// DefaultDorksPath chemin par défaut du fichier dorks exporté.
func DefaultDorksPath(baseDir string) string {
	if baseDir == "" {
		baseDir = "results"
	}
	return filepath.Join(baseDir, "dorks_ch.txt")
}
