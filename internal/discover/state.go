package discover

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// CursorState curseur Bing persisté entre les runs daily (nouveaux résultats chaque jour).
type CursorState struct {
	Page int `json:"page"`
}

func cursorPath(baseDir string) string {
	if baseDir == "" {
		baseDir = "results"
	}
	return filepath.Join(baseDir, "discover_cursor.json")
}

// LoadCursor charge le curseur de pagination (0 si absent).
func LoadCursor(baseDir string) (int, error) {
	path := cursorPath(baseDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	var st CursorState
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, err
	}
	if st.Page < 0 {
		return 0, nil
	}
	return st.Page, nil
}

// SaveCursor enregistre la position pour le prochain run.
func SaveCursor(baseDir string, page int) error {
	if page < 0 {
		page = 0
	}
	path := cursorPath(baseDir)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.Marshal(CursorState{Page: page})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// DaySeed rotation quotidienne des dorks (0 = aujourd'hui).
func DaySeed(custom int) int {
	if custom != 0 {
		return custom
	}
	now := time.Now()
	return now.YearDay() + now.Year()*400
}
