package scanctl

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Tier passe scan hunt (scope_hunt.txt).
type Tier string

const TierHunt Tier = "hunt"

var (
	ErrInvalidTier    = errors.New("tier invalide: hunt")
	ErrAlreadyRunning = errors.New("scan déjà en cours")
)

// Root répertoire sqli-hunter (binaire + scripts).
func Root(resultsDir string) string {
	if v := strings.TrimSpace(os.Getenv("SQLI_HUNTER_ROOT")); v != "" {
		return v
	}
	if resultsDir != "" {
		if abs, err := filepath.Abs(resultsDir); err == nil {
			return filepath.Dir(abs)
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func normalizeTier(t string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "hunt", "weekly", "monthly", "big":
		return TierHunt, nil
	default:
		return "", ErrInvalidTier
	}
}

// Start lance un scan hunt en arrière-plan via scan.sh.
func Start(resultsDir string, tier string, extraArgs ...string) (string, error) {
	if _, err := normalizeTier(tier); err != nil {
		return "", err
	}
	root := Root(resultsDir)
	script := filepath.Join(root, "scan.sh")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("scan.sh introuvable dans %s", root)
	}
	args := append([]string{"hunt"}, extraArgs...)
	cmd := exec.Command(script, args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"SQLI_HUNTER_ROOT="+root,
		"SQLI_HUNTER_ENV="+filepath.Join(root, "sqli-hunter.env"),
	)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if strings.Contains(text, "ALREADY_RUNNING") {
			return text, ErrAlreadyRunning
		}
		if text == "" {
			return "", err
		}
		return text, fmt.Errorf("%s: %w", text, err)
	}
	return text, nil
}

// Stop arrête les scans en cours via stop-scans.sh ou scan.sh stop.
func Stop(resultsDir string) (string, error) {
	root := Root(resultsDir)
	for _, name := range []string{"stop-scans.sh", "scan.sh"} {
		script := filepath.Join(root, name)
		if _, err := os.Stat(script); err != nil {
			continue
		}
		args := []string{}
		if name == "scan.sh" {
			args = []string{"stop"}
		}
		cmd := exec.Command(script, args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		text := strings.TrimSpace(string(out))
		if err != nil && text == "" {
			return "", err
		}
		return text, nil
	}
	return "", fmt.Errorf("stop-scans.sh introuvable dans %s", root)
}

// Status liste les processus sqli-hunter actifs.
func Status(resultsDir string) (string, error) {
	root := Root(resultsDir)
	script := filepath.Join(root, "scan.sh")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("scan.sh introuvable dans %s", root)
	}
	cmd := exec.Command(script, "status")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, err
	}
	if text == "" {
		return "IDLE", nil
	}
	return text, nil
}

// Running indique si un scan hunt tourne.
func Running(resultsDir string) (bool, string, error) {
	text, err := Status(resultsDir)
	if err != nil {
		return false, "", err
	}
	if text == "IDLE" || text == "(aucun)" {
		return false, text, nil
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "sqli-hunter hunt") {
			return true, line, nil
		}
	}
	return false, text, nil
}

// ParseStarted extrait pid/log depuis la sortie de scan.sh.
func ParseStarted(out string) (tier, pid, log string) {
	tier = "hunt"
	fields := strings.Fields(out)
	for _, f := range fields {
		if strings.HasPrefix(f, "pid=") {
			pid = strings.TrimPrefix(f, "pid=")
		}
		if strings.HasPrefix(f, "log=") {
			log = strings.TrimPrefix(f, "log=")
		}
	}
	if len(fields) >= 2 && fields[0] == "STARTED" {
		tier = fields[1]
	}
	return tier, pid, log
}

// HasIdleOutput indique qu'aucun scan ne tournait à l'arrêt.
func HasIdleOutput(out string) bool {
	out = strings.TrimSpace(out)
	return out == "" || strings.Contains(out, "(aucun)") || strings.Contains(out, "scans arrêtés")
}

// FormatLines nettoie une sortie shell pour Telegram.
func FormatLines(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return ""
	}
	var b bytes.Buffer
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(line)
	}
	return b.String()
}
