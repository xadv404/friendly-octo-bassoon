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

// CursorKind sélectionne le fichier curseur persisté.
type CursorKind int

const (
	CursorDaily CursorKind = iota
	CursorBig      // hebdo (weekly)
	CursorMonthly
)

func cursorPath(baseDir string, kind CursorKind) string {
	if baseDir == "" {
		baseDir = "results"
	}
	name := "discover_cursor.json"
	switch kind {
	case CursorBig:
		name = "discover_cursor_big.json"
	case CursorMonthly:
		name = "discover_cursor_monthly.json"
	}
	return filepath.Join(baseDir, name)
}

// LoadCursor charge le curseur daily (0 si absent).
func LoadCursor(baseDir string) (int, error) {
	return LoadCursorKind(baseDir, CursorDaily)
}

// LoadCursorKind charge un curseur typé.
func LoadCursorKind(baseDir string, kind CursorKind) (int, error) {
	path := cursorPath(baseDir, kind)
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

// SaveCursor enregistre le curseur daily.
func SaveCursor(baseDir string, page int) error {
	return SaveCursorKind(baseDir, CursorDaily, page)
}

// SaveCursorKind enregistre un curseur typé.
func SaveCursorKind(baseDir string, kind CursorKind, page int) error {
	if page < 0 {
		page = 0
	}
	path := cursorPath(baseDir, kind)
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

// WeekSeed rotation hebdomadaire pour le mode big.
func WeekSeed(custom int) int {
	if custom != 0 {
		return custom
	}
	now := time.Now()
	_, week := now.ISOWeek()
	return week + now.Year()*100
}

// MonthSeed rotation mensuelle pour le mode monthly.
func MonthSeed(custom int) int {
	if custom != 0 {
		return custom
	}
	now := time.Now()
	return int(now.Month()) + now.Year()*100
}

// BigTier niveau d'agressivité discover (weekly / monthly).
type BigTier int

const (
	BigTierWeekly BigTier = iota
	BigTierMonthly
)

// DefaultMaxPages retourne la limite de pages discover pour un profil.
func DefaultMaxPages(set DorkSet, tier BigTier) int {
	if set != DorkSetBig {
		return 400
	}
	switch tier {
	case BigTierMonthly:
		return 3000
	default:
		return 1500
	}
}

// DefaultDiscoverLimit URLs à collecter selon le tier big.
func DefaultDiscoverLimit(tier BigTier) int {
	switch tier {
	case BigTierMonthly:
		return 80000
	default:
		return 40000
	}
}
