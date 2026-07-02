package results

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
)

// ProviderInfo stats d'un fournisseur email.
type ProviderInfo struct {
	Provider string
	Count    int
}

var providerAliases = map[string]string{
	"gmail":      "gmail.com",
	"googlemail": "gmail.com",
	"bluewin":    "bluewin.ch",
	"icloud":     "icloud.com",
	"sunrise":    "sunrise.ch",
	"hispeed":    "hispeed.ch",
	"hotmail":    "hotmail.com",
	"outlook":    "outlook.com",
	"yahoo":      "yahoo.com",
	"gmx":        "gmx.ch",
}

// EmailsDir retourne le chemin results/emails/.
func EmailsDir(baseDir string) string {
	if baseDir == "" {
		baseDir = "results"
	}
	return filepath.Join(baseDir, "emails")
}

// ListProviders liste les fournisseurs disponibles (emails uniques non livrés).
func ListProviders(baseDir string) ([]ProviderInfo, error) {
	dir := EmailsDir(baseDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	delivered, _ := NewDeliveredRegistry(baseDir)

	var out []ProviderInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		provider := strings.TrimSuffix(e.Name(), ".txt")
		n, err := countUniqueEmails(filepath.Join(dir, e.Name()), delivered)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			continue
		}
		out = append(out, ProviderInfo{Provider: provider, Count: n})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	return out, nil
}

// ResolveProvider trouve le fichier fournisseur depuis une requête (gmail, gmail.com…).
func ResolveProvider(baseDir, query string) (string, error) {
	query = normalizeProviderQuery(query)
	if query == "" {
		return "", fmt.Errorf("fournisseur vide")
	}

	if alias, ok := providerAliases[query]; ok {
		query = alias
	}

	dir := EmailsDir(baseDir)
	path := filepath.Join(dir, query+".txt")
	if _, err := os.Stat(path); err == nil {
		return query, nil
	}

	providers, err := ListProviders(baseDir)
	if err != nil {
		return "", err
	}
	if len(providers) == 0 {
		return "", fmt.Errorf("aucun email disponible dans %s", dir)
	}

	var matches []string
	for _, p := range providers {
		name := p.Provider
		base := strings.SplitN(name, ".", 2)[0]
		if name == query || base == query || strings.HasPrefix(name, query+".") {
			matches = append(matches, name)
		}
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("fournisseur inconnu: %s", query)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("fournisseur ambigu %q (%s)", query, strings.Join(matches, ", "))
	}
}

// ReadProviderEmails lit jusqu'à limit emails d'un fournisseur (0 = tous).
func ReadProviderEmails(baseDir, provider string, limit int) ([]string, error) {
	resolved, err := ResolveProvider(baseDir, provider)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(EmailsDir(baseDir), resolved+".txt")
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var emails []string
	seen := make(map[string]struct{})
	delivered, _ := NewDeliveredRegistry(baseDir)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || !strings.Contains(line, "@") {
			continue
		}
		if !extractor.ValidEmail(line) {
			continue
		}
		if delivered != nil && delivered.Contains(line) {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		emails = append(emails, line)
		if limit > 0 && len(emails) >= limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(emails) == 0 {
		return nil, fmt.Errorf("aucun email pour %s", resolved)
	}
	return emails, nil
}

// ParseEmailRequest parse « 100 gmail » ou « gmail 100 ».
func ParseEmailRequest(text string) (count int, provider string, ok bool) {
	text = strings.TrimSpace(strings.ToLower(text))
	if text == "" {
		return 0, "", false
	}
	parts := strings.Fields(text)
	if len(parts) != 2 {
		return 0, "", false
	}

	if n, err := strconv.Atoi(parts[0]); err == nil {
		return n, parts[1], n > 0
	}
	if n, err := strconv.Atoi(parts[1]); err == nil {
		return n, parts[0], n > 0
	}
	return 0, "", false
}

func normalizeProviderQuery(q string) string {
	q = strings.ToLower(strings.TrimSpace(q))
	q = strings.TrimPrefix(q, "@")
	q = strings.TrimSuffix(q, ".txt")
	return q
}
