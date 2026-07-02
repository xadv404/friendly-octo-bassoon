package discover

import "strings"

func isBingBlocked(html string) bool {
	return isSearchBlocked(html)
}

func isGoogleEnableJS(html string) bool {
	lower := strings.ToLower(html)
	return strings.Contains(lower, "/httpservice/retry/enablejs") ||
		strings.Contains(lower, "enablejs=1")
}

func isGoogleHardBlocked(html string) bool {
	if isSearchBlocked(html) {
		return true
	}
	lower := strings.ToLower(html)
	for _, marker := range []string{
		"google.com/sorry",
		"/sorry/index",
		"emsg=sg_rel",
		"unusual traffic from your computer network",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func isGoogleBlocked(html string) bool {
	return isGoogleHardBlocked(html) || isGoogleEnableJS(html)
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
