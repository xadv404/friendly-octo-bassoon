package results

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DumpRegistry suit les domaines déjà dumpés (pas de re-dump).
type DumpRegistry struct {
	path    string
	mu      sync.RWMutex
	domains map[string]struct{}
}

// NewDumpRegistry charge results/dumped_domains.txt.
func NewDumpRegistry(baseDir string) (*DumpRegistry, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	r := &DumpRegistry{
		path:    filepath.Join(baseDir, "dumped_domains.txt"),
		domains: make(map[string]struct{}),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *DumpRegistry) load() error {
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
		d := strings.ToLower(strings.TrimSpace(sc.Text()))
		if d != "" && !strings.HasPrefix(d, "#") {
			r.domains[d] = struct{}{}
		}
	}
	return sc.Err()
}

// Contains indique si le domaine a déjà été dumpé.
func (r *DumpRegistry) Contains(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.domains[domain]
	return ok
}

// Mark enregistre un domaine comme dumpé (persistant).
func (r *DumpRegistry) Mark(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.domains[domain]; ok {
		return nil
	}
	r.domains[domain] = struct{}{}

	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(domain + "\n")
	return err
}

// Count retourne le nombre de domaines dumpés.
func (r *DumpRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.domains)
}
