package discover

import (
	"os"
	"strconv"
)

// MaxPagesPerRun — dorks à traiter par passe pour couvrir tout le catalogue en cycleWeeks
// (en supposant ~1 lancement par semaine).
func MaxPagesPerRun(cycleWeeks, totalDorks int) int {
	cycleWeeks = ClampCycleWeeks(cycleWeeks)
	if totalDorks <= 0 {
		return 0
	}
	return (totalDorks + cycleWeeks - 1) / cycleWeeks
}

// ClampCycleWeeks borne le cycle à 1–4 semaines.
func ClampCycleWeeks(n int) int {
	if n < 1 {
		return 1
	}
	if n > 4 {
		return 4
	}
	return n
}

// CycleWeeksFromEnv lit HUNT_CYCLE_WEEKS (défaut 2).
func CycleWeeksFromEnv() int {
	v := os.Getenv("HUNT_CYCLE_WEEKS")
	if v == "" {
		return 2
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 2
	}
	return ClampCycleWeeks(n)
}
