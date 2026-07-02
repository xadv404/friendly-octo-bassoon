package results

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// EmailWriter écrit les emails extraits dans un fichier par fournisseur (gmail.com.txt, bluewin.ch.txt…).
type EmailWriter struct {
	dir   string
	mu    sync.Mutex
	seen  map[string]map[string]struct{}
	files map[string]*os.File
}

// NewEmailWriter crée results/emails/.
func NewEmailWriter(baseDir string) (*EmailWriter, error) {
	dir := filepath.Join(baseDir, "emails")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &EmailWriter{
		dir:   dir,
		seen:  make(map[string]map[string]struct{}),
		files: make(map[string]*os.File),
	}, nil
}

// Append ajoute un email dans le fichier du fournisseur (@domain).
func (w *EmailWriter) Append(email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if !extractor.ValidEmail(email) {
		return nil
	}
	provider := EmailProvider(email)
	if provider == "" {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.seen[provider] == nil {
		w.seen[provider] = make(map[string]struct{})
	}
	if _, ok := w.seen[provider][email]; ok {
		return nil
	}
	w.seen[provider][email] = struct{}{}

	f, ok := w.files[provider]
	if !ok {
		path := filepath.Join(w.dir, provider+".txt")
		var err error
		f, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		w.files[provider] = f
	}
	_, err := fmt.Fprintln(f, email)
	return err
}

// Close ferme tous les fichiers et retourne leurs chemins.
func (w *EmailWriter) Close() ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var paths []string
	for provider, f := range w.files {
		if err := f.Close(); err != nil {
			return paths, err
		}
		paths = append(paths, filepath.Join(w.dir, provider+".txt"))
	}
	w.files = make(map[string]*os.File)
	return paths, nil
}

// EmailProvider retourne le domaine après @ (gmail.com, bluewin.ch…).
func EmailProvider(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	provider := strings.Trim(email[at+1:], ".")
	if provider == "" {
		return ""
	}
	return sanitizeDomain(provider)
}

// EmailFromExtraction lit l'email depuis une extraction PII (adresse seule, sans préfixe).
func EmailFromExtraction(d models.ExtractedData) string {
	var email string
	if d.PII != nil && d.PII.Email != "" {
		email = strings.ToLower(strings.TrimSpace(d.PII.Email))
	} else {
		for _, line := range strings.Split(d.Value, "\n") {
			line = strings.ToLower(strings.TrimSpace(line))
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "email:") {
				line = strings.TrimSpace(line[len("email:"):])
			}
			if strings.Contains(line, "@") {
				email = line
				break
			}
		}
	}
	if email == "" || !extractor.ValidEmail(email) {
		return ""
	}
	return email
}

// WriteEmailsFromTargets écrit les emails groupés par fournisseur.
func WriteEmailsFromTargets(baseDir string, targets []TargetResult) ([]string, error) {
	w, err := NewEmailWriter(baseDir)
	if err != nil {
		return nil, err
	}
	dump, _ := NewDumpRegistry(baseDir)
	for _, t := range targets {
		for _, e := range t.Extractions {
			if e.DataType != models.DataPII {
				continue
			}
			if em := EmailFromExtraction(e); em != "" {
				if err := w.Append(em); err != nil {
					return nil, err
				}
				if domain, err := DomainFromURL(t.URL); err == nil {
					_ = dump.Mark(domain)
				}
			}
		}
	}
	return w.Close()
}
