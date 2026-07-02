package results

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
)

// DeliveredRegistry emails déjà envoyés via le bot (jamais renvoyer).
type DeliveredRegistry struct {
	path   string
	mu     sync.RWMutex
	emails map[string]struct{}
}

// NewDeliveredRegistry charge results/bot_delivered.txt.
func NewDeliveredRegistry(baseDir string) (*DeliveredRegistry, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	r := &DeliveredRegistry{
		path:   filepath.Join(baseDir, "bot_delivered.txt"),
		emails: make(map[string]struct{}),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *DeliveredRegistry) load() error {
	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		em := normalizeEmailLine(sc.Text())
		if em != "" {
			r.emails[em] = struct{}{}
		}
	}
	return sc.Err()
}

func (r *DeliveredRegistry) Contains(email string) bool {
	em := normalizeEmailLine(email)
	if em == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.emails[em]
	return ok
}

func (r *DeliveredRegistry) MarkMany(emails []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var toWrite []string
	for _, email := range emails {
		em := normalizeEmailLine(email)
		if em == "" {
			continue
		}
		if _, ok := r.emails[em]; ok {
			continue
		}
		r.emails[em] = struct{}{}
		toWrite = append(toWrite, em)
	}
	if len(toWrite) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, em := range toWrite {
		if _, err := f.WriteString(em + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// BotTakeResult emails pris du stock pour envoi bot.
type BotTakeResult struct {
	Provider string
	Emails   []string
}

// TakeEmailsForBot prend des emails uniques, retire du stock et marque comme livrés.
func TakeEmailsForBot(baseDir, providerQuery string, limit int) (BotTakeResult, error) {
	if limit <= 0 {
		return BotTakeResult{}, fmt.Errorf("limite invalide")
	}
	resolved, err := ResolveProvider(baseDir, providerQuery)
	if err != nil {
		return BotTakeResult{}, err
	}

	delivered, err := NewDeliveredRegistry(baseDir)
	if err != nil {
		return BotTakeResult{}, err
	}

	path := filepath.Join(EmailsDir(baseDir), resolved+".txt")
	lines, err := readEmailLines(path)
	if err != nil {
		return BotTakeResult{}, err
	}

	taken, remaining := pickAndSplit(lines, limit, delivered)
	if len(taken) == 0 {
		return BotTakeResult{}, fmt.Errorf("aucun email disponible pour %s (stock vide ou déjà livrés)", resolved)
	}

	if err := writeEmailLines(path, remaining); err != nil {
		return BotTakeResult{}, err
	}
	if err := delivered.MarkMany(taken); err != nil {
		return BotTakeResult{}, err
	}

	return BotTakeResult{Provider: resolved, Emails: taken}, nil
}

// CompactAllEmails déduplique chaque fichier et retire doublons inter-fichiers / déjà livrés.
func CompactAllEmails(baseDir string) error {
	dir := EmailsDir(baseDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	delivered, err := NewDeliveredRegistry(baseDir)
	if err != nil {
		return err
	}
	globalKept := make(map[string]struct{})
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		provider := strings.TrimSuffix(e.Name(), ".txt")
		path := filepath.Join(dir, e.Name())
		lines, err := readEmailLines(path)
		if err != nil {
			return err
		}
		unique := dedupeProviderLines(lines, provider, delivered, globalKept)
		if err := writeEmailLines(path, unique); err != nil {
			return err
		}
	}
	return nil
}

func dedupeProviderLines(lines []string, provider string, delivered *DeliveredRegistry, global map[string]struct{}) []string {
	var out []string
	fileSeen := make(map[string]struct{})
	for _, line := range lines {
		em := normalizeEmailLine(line)
		if em == "" {
			continue
		}
		if EmailProvider(em) != provider {
			continue
		}
		if delivered != nil && delivered.Contains(em) {
			continue
		}
		if _, ok := fileSeen[em]; ok {
			continue
		}
		if _, ok := global[em]; ok {
			continue
		}
		fileSeen[em] = struct{}{}
		global[em] = struct{}{}
		out = append(out, em)
	}
	return out
}

func pickAndSplit(lines []string, limit int, delivered *DeliveredRegistry) (taken, remaining []string) {
	fileSeen := make(map[string]struct{})
	for _, line := range lines {
		em := normalizeEmailLine(line)
		if em == "" {
			continue
		}
		if _, ok := fileSeen[em]; ok {
			continue
		}
		fileSeen[em] = struct{}{}

		if delivered.Contains(em) {
			continue
		}

		if len(taken) < limit {
			taken = append(taken, em)
			continue
		}
		remaining = append(remaining, em)
	}
	return taken, remaining
}

func readEmailLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func writeEmailLines(path string, emails []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, em := range emails {
		if _, err := fmt.Fprintln(f, em); err != nil {
			return err
		}
	}
	return nil
}

func normalizeEmailLine(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || !extractor.ValidEmail(s) {
		return ""
	}
	return s
}

func countUniqueEmails(path string, delivered *DeliveredRegistry) (int, error) {
	lines, err := readEmailLines(path)
	if err != nil {
		return 0, err
	}
	seen := make(map[string]struct{})
	n := 0
	for _, line := range lines {
		em := normalizeEmailLine(line)
		if em == "" {
			continue
		}
		if delivered != nil && delivered.Contains(em) {
			continue
		}
		if _, ok := seen[em]; ok {
			continue
		}
		seen[em] = struct{}{}
		n++
	}
	return n, nil
}
