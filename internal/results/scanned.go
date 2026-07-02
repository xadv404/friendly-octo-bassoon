package results

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ScannedRegistry suit les URLs déjà scannées (évite re-scan quotidien).
type ScannedRegistry struct {
	path string
	mu   sync.RWMutex
	urls map[string]struct{}
}

// NewScannedRegistry charge results/scanned_urls.txt.
func NewScannedRegistry(baseDir string) (*ScannedRegistry, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	r := &ScannedRegistry{
		path: filepath.Join(baseDir, "scanned_urls.txt"),
		urls: make(map[string]struct{}),
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *ScannedRegistry) load() error {
	f, err := os.Open(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		u := normalizeScannedURL(sc.Text())
		if u != "" {
			r.urls[u] = struct{}{}
		}
	}
	return sc.Err()
}

// Contains indique si l'URL a déjà été scannée.
func (r *ScannedRegistry) Contains(raw string) bool {
	u := normalizeScannedURL(raw)
	if u == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.urls[u]
	return ok
}

// Mark enregistre une URL scannée.
func (r *ScannedRegistry) Mark(raw string) error {
	u := normalizeScannedURL(raw)
	if u == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.urls[u]; ok {
		return nil
	}
	r.urls[u] = struct{}{}

	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(u + "\n")
	return err
}

// Count retourne le nombre d'URLs scannées.
func (r *ScannedRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.urls)
}

func normalizeScannedURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.Scheme == "http" && strings.HasSuffix(u.Host, ":80") {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	return u.String()
}
