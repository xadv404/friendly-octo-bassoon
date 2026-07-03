package results

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RunStatus progression daily/discover/scan (lu par le bot /status).
type RunStatus struct {
	Phase        string    `json:"phase"`
	UpdatedAt    time.Time `json:"updated_at"`
	DorkIndex    int       `json:"dork_index,omitempty"`
	DorkTotal    int       `json:"dork_total,omitempty"`
	URLsKept     int       `json:"urls_kept,omitempty"`
	URLsFetched  int       `json:"urls_fetched,omitempty"`
	URLsSkipped  int       `json:"urls_skipped,omitempty"`
	DiscoverPage int       `json:"discover_page,omitempty"`
	Scanned      int       `json:"scanned,omitempty"`
	ScanTotal    int       `json:"scan_total,omitempty"`
	Vulns        int       `json:"vulns,omitempty"`
	Findings     int       `json:"findings,omitempty"`
	NewEmails    int       `json:"new_emails,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

func runStatusPath(dir string) string {
	return filepath.Join(dir, "run_status.json")
}

// WriteRunStatus persiste l'état courant (best-effort).
func WriteRunStatus(dir string, st RunStatus) error {
	if dir == "" {
		dir = "results"
	}
	st.UpdatedAt = time.Now().UTC()
	if st.Phase == "" {
		st.Phase = "idle"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := runStatusPath(dir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, runStatusPath(dir))
}

// LoadRunStatus lit run_status.json s'il existe.
func LoadRunStatus(dir string) (RunStatus, bool) {
	if dir == "" {
		dir = "results"
	}
	b, err := os.ReadFile(runStatusPath(dir))
	if err != nil {
		return RunStatus{}, false
	}
	var st RunStatus
	if json.Unmarshal(b, &st) != nil {
		return RunStatus{}, false
	}
	return st, true
}

// CountLines fichier texte (une ligne = un enregistrement).
func CountLines(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}
