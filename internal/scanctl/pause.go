package scanctl

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// ErrNotRunning aucun scan hunt actif.
var ErrNotRunning = errors.New("aucun scan en cours")

func huntPID(resultsDir string) (int, error) {
	running, line, err := Running(resultsDir)
	if err != nil {
		return 0, err
	}
	if !running {
		return 0, ErrNotRunning
	}
	return parsePIDFromLine(line)
}

func parsePIDFromLine(line string) (int, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return 0, ErrNotRunning
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return 0, ErrNotRunning
	}
	return pid, nil
}

// IsPaused indique si le scan hunt est en pause (SIGSTOP).
func IsPaused(resultsDir string) bool {
	pid, err := huntPID(resultsDir)
	if err != nil {
		return false
	}
	return processStopped(pid)
}

func processStopped(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "State:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			return fields[1] == "T" || strings.HasPrefix(fields[1], "T(")
		}
	}
	return false
}

// TogglePause bascule pause/reprise du scan hunt (SIGSTOP/SIGCONT).
func TogglePause(resultsDir string) (paused bool, err error) {
	pid, err := huntPID(resultsDir)
	if err != nil {
		return false, err
	}
	if processStopped(pid) {
		return false, syscall.Kill(pid, syscall.SIGCONT)
	}
	return true, syscall.Kill(pid, syscall.SIGSTOP)
}
