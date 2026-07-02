package discover

import (
	"strings"
	"testing"
)

func TestGoogleSearchStrategies(t *testing.T) {
	if len(googleSearchStrategies()) < 4 {
		t.Fatalf("expected multiple strategies, got %d", len(googleSearchStrategies()))
	}
}

func TestBuildGoogleSearchURL(t *testing.T) {
	u, err := buildGoogleSearchURL(googleSearchStrategies()[0], "site:.ch inurl:id=", 10)
	if err != nil {
		t.Fatal(err)
	}
	if u == "" || !strings.Contains(u, "gbv=1") || !strings.Contains(u, "start=10") {
		t.Fatalf("bad url: %s", u)
	}
}

func TestIsGoogleRetryable(t *testing.T) {
	if !isGoogleRetryable(errString("google HTTP 429")) {
		t.Fatal("429 should retry")
	}
	if isGoogleRetryable(nil) {
		t.Fatal("nil should not retry")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
