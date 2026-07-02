package results

import (
	"os"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

// SiteStore écrit les emails extraits au fil de l'eau (adapté 1k–100k URLs).
type SiteStore struct {
	baseDir string
	emails  *EmailWriter
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
	return &SiteStore{
		baseDir: baseDir,
		emails:  emails,
	}, nil
}

// AppendExtraction enregistre un email extrait.
func (s *SiteStore) AppendExtraction(findingURL string, d models.ExtractedData) {
	if d.DataType == models.DataPII {
		if em := EmailFromExtraction(d); em != "" {
			_ = s.emails.Append(em)
		}
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
