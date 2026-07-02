package discover

import "strings"

func isBingBlocked(html string) bool {
	return isSearchBlocked(html)
}

func isGoogleBlocked(html string) bool {
	if isSearchBlocked(html) {
		return true
	}
	lower := strings.ToLower(html)
	for _, marker := range []string{
		"google.com/sorry",
		"/httpservice/retry/enablejs",
		"emsg=sg_rel",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isSearchBlocked(html string) bool {
	lower := strings.ToLower(html)
	for _, marker := range []string{
		"captcha",
		"challenges",
		"verify you are human",
		"unusual traffic",
		"turnstile",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
