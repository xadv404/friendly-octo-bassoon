package results

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// SiteStore écrit les résultats au fil de l'eau (adapté 1k–100k URLs).
type SiteStore struct {
	baseDir    string
	version    string
	mu         sync.Mutex
	domains    map[string]*domainWriter
	extractions map[string][]models.ExtractedData // keyed by finding URL
	extMu      sync.Mutex
}

type domainWriter struct {
	domain      string
	dir         string
	jsonl       *os.File
	sql         *os.File
	urlsScanned int
	urlsVuln    int
	findings    int
	extractions int
}

// NewSiteStore crée un store de résultats streaming.
func NewSiteStore(baseDir, version string) (*SiteStore, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}
	return &SiteStore{
		baseDir:     baseDir,
		version:     version,
		domains:     make(map[string]*domainWriter),
		extractions: make(map[string][]models.ExtractedData),
	}, nil
}

// AppendExtraction stocke une extraction en attente pour une URL.
func (s *SiteStore) AppendExtraction(findingURL string, d models.ExtractedData) {
	s.extMu.Lock()
	s.extractions[findingURL] = append(s.extractions[findingURL], d)
	s.extMu.Unlock()
}

func (s *SiteStore) takeExtractions(url string) []models.ExtractedData {
	s.extMu.Lock()
	defer s.extMu.Unlock()
	ext := s.extractions[url]
	delete(s.extractions, url)
	return ext
}

// Add enregistre le résultat d'une URL (écriture immédiate sur disque).
func (s *SiteStore) Add(tr TargetResult) error {
	tr.Extractions = append(tr.Extractions, s.takeExtractions(tr.URL)...)

	domain, err := DomainFromURL(tr.URL)
	if err != nil {
		domain = "unknown"
	}

	s.mu.Lock()
	dw, err := s.getDomainWriter(domain)
	s.mu.Unlock()
	if err != nil {
		return err
	}

	return dw.append(tr)
}

func (s *SiteStore) getDomainWriter(domain string) (*domainWriter, error) {
	dw, ok := s.domains[domain]
	if ok {
		return dw, nil
	}
	dir := filepath.Join(s.baseDir, domain)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	jsonl, err := os.OpenFile(filepath.Join(dir, domain+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	sql, err := os.OpenFile(filepath.Join(dir, domain+".sql"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		jsonl.Close()
		return nil, err
	}
	dw = &domainWriter{domain: domain, dir: dir, jsonl: jsonl, sql: sql}
	s.domains[domain] = dw
	return dw, nil
}

func (dw *domainWriter) append(tr TargetResult) error {
	line, err := json.Marshal(tr)
	if err != nil {
		return err
	}
	if _, err := dw.jsonl.Write(append(line, '\n')); err != nil {
		return err
	}
	dw.urlsScanned++
	dw.findings += len(tr.Findings)
	dw.extractions += len(tr.Extractions)
	if len(tr.Findings) > 0 {
		dw.urlsVuln++
		if _, err := dw.sql.WriteString(formatSQLTarget(tr)); err != nil {
			return err
		}
	}
	return nil
}

// Finalize ferme les flux et produit DOMAIN.json + DOMAIN.sql final.
func (s *SiteStore) Finalize() ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var written []string
	for domain, dw := range s.domains {
		if err := dw.jsonl.Close(); err != nil {
			return written, err
		}
		if err := dw.sql.Close(); err != nil {
			return written, err
		}

		targets, err := readJSONL(filepath.Join(dw.dir, domain+".jsonl"))
		if err != nil {
			return written, err
		}

		report := SiteReport{
			Domain:      domain,
			ToolVersion: s.version,
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Summary: SiteSummary{
				URLsScanned:    dw.urlsScanned,
				URLsVulnerable: dw.urlsVuln,
				Findings:       dw.findings,
				Extractions:    dw.extractions,
			},
			Targets: targets,
		}

		jsonPath := filepath.Join(dw.dir, domain+".json")
		if err := writeJSON(jsonPath, report); err != nil {
			return written, err
		}
		written = append(written, jsonPath)

		// Réécrire SQL complet avec en-tête
		sqlPath := filepath.Join(dw.dir, domain+".sql")
		if err := os.WriteFile(sqlPath, []byte(formatSQL(report)), 0644); err != nil {
			return written, err
		}
		written = append(written, sqlPath)

		os.Remove(filepath.Join(dw.dir, domain+".jsonl"))
	}
	return written, nil
}

func readJSONL(path string) ([]TargetResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []TargetResult
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var tr TargetResult
		if err := json.Unmarshal(sc.Bytes(), &tr); err != nil {
			continue
		}
		out = append(out, tr)
	}
	return out, sc.Err()
}

func formatSQLTarget(tr TargetResult) string {
	if len(tr.Findings) == 0 && len(tr.Extractions) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("/* " + strings.Repeat("=", 60) + " */\n")
	fmt.Fprintf(&b, "/* URL: %s */\n", tr.URL)
	for _, f := range tr.Findings {
		fmt.Fprintf(&b, "/* VULN: %s | param: %s | confidence: %s */\n",
			f.VulnType, f.Parameter, f.Confidence)
	}
	b.WriteString("/* " + strings.Repeat("=", 60) + " */\n")
	seen := make(map[string]bool)
	for _, e := range tr.Extractions {
		key := string(e.DataType) + ":" + e.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(&b, "-- %s: %s\n", e.DataType, escapeSQLComment(e.Value))
	}
	b.WriteByte('\n')
	return b.String()
}
