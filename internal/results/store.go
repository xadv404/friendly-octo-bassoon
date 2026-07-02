package results

import (
	"os"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// SiteStore écrit les emails extraits au fil de l'eau (adapté 1k–100k URLs).
type SiteStore struct {
	baseDir string
	emails  *EmailWriter
	dump    *DumpRegistry
	scanned *ScannedRegistry
}

// NewSiteStore crée un store de résultats (emails uniquement).
func NewSiteStore(baseDir, version string) (*SiteStore, error) {
	if baseDir == "" {
		baseDir = "results"
	}
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, err
	}
	emails, err := NewEmailWriter(baseDir)
	if err != nil {
		return nil, err
	}
	dump, err := NewDumpRegistry(baseDir)
	if err != nil {
		return nil, err
	}
	scanned, err := NewScannedRegistry(baseDir)
	if err != nil {
		return nil, err
	}
	return &SiteStore{
		baseDir: baseDir,
		emails:  emails,
		dump:    dump,
		scanned: scanned,
	}, nil
}

// IsDomainDumped indique si un domaine a déjà été dumpé.
func (s *SiteStore) IsDomainDumped(domain string) bool {
	return s.dump != nil && s.dump.Contains(domain)
}

// IsURLScanned indique si l'URL a déjà été scannée.
func (s *SiteStore) IsURLScanned(raw string) bool {
	return s.scanned != nil && s.scanned.Contains(raw)
}

// MarkURLScanned enregistre une URL scannée.
func (s *SiteStore) MarkURLScanned(raw string) {
	if s.scanned != nil {
		_ = s.scanned.Mark(raw)
	}
}

// NewEmails retourne le nombre d'emails nouveaux cette session.
func (s *SiteStore) NewEmails() int {
	if s.emails == nil {
		return 0
	}
	return s.emails.NewCount()
}

// AppendExtraction enregistre un email extrait et marque le domaine dumpé.
func (s *SiteStore) AppendExtraction(findingURL string, d models.ExtractedData) {
	if d.DataType != models.DataPII {
		return
	}
	em := EmailFromExtraction(d)
	if em == "" {
		return
	}
	_ = s.emails.Append(em)
	if domain, err := DomainFromURL(findingURL); err == nil {
		_ = s.dump.Mark(domain)
	}
}

// Add est conservé pour compatibilité avec le runner massif (no-op).
func (s *SiteStore) Add(tr TargetResult) error {
	return nil
}

// Finalize ferme les fichiers emails.
func (s *SiteStore) Finalize() ([]string, error) {
	if s.emails == nil {
		return nil, nil
	}
	return s.emails.Close()
}
