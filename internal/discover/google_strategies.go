package discover

import (
	"math/rand"
	"strings"
	"time"
)

const (
	googleHomeURL    = "https://www.google.ch/"
	googleMaxRetry   = 20
	googleResultsNum = 10
)

type googleSearchStrategy struct {
	baseURL string
	params  map[string]string
	label   string
}

func googleSearchStrategies() []googleSearchStrategy {
	return []googleSearchStrategy{
		{
			baseURL: "https://www.google.ch/search",
			label:   "ch-gbv1-udm14",
			params: map[string]string{
				"gbv": "1",
				"udm": "14",
			},
		},
		{
			baseURL: "https://www.google.ch/search",
			label:   "ch-gbv2",
			params: map[string]string{
				"gbv": "2",
			},
		},
		{
			baseURL: "https://www.google.com/search",
			label:   "com-gbv1-udm14",
			params: map[string]string{
				"gbv": "1",
				"udm": "14",
			},
		},
		{
			baseURL: "https://www.google.ch/search",
			label:   "ch-firefox",
			params: map[string]string{
				"gbv":    "1",
				"client": "firefox-b-d",
			},
		},
		{
			baseURL: "https://www.google.ch/search",
			label:   "ch-ie",
			params: map[string]string{
				"gbv": "1",
				"ie":  "UTF-8",
				"oe":  "UTF-8",
			},
		},
	}
}

func googleJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return base/2 + time.Duration(rand.Int63n(int64(base/2+1)))
}

func googleRetryDelay(attempt int) time.Duration {
	sec := attempt
	if sec > 8 {
		sec = 8
	}
	return googleJitter(time.Duration(sec) * time.Second)
}

func isGoogleRetryable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"429", "sorry", "enablejs", "blocage", "vide", "consent",
		"headless", "timeout", "navigated", "destroyed", "closed",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}
