package payloads

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestGetPayloads_AllTechniques(t *testing.T) {
	payloads := GetPayloads(AllTechniques(), false, nil)
	if len(payloads) != 4 {
		t.Fatalf("expected 4 techniques, got %d", len(payloads))
	}
	if len(payloads[models.ErrorBased]) == 0 {
		t.Fatal("expected error payloads")
	}
}

func TestGetPayloads_WAF(t *testing.T) {
	without := GetPayloads([]models.InjectionType{models.ErrorBased}, false, nil)
	with := GetPayloads([]models.InjectionType{models.ErrorBased}, true, nil)
	if len(with[models.ErrorBased]) <= len(without[models.ErrorBased]) {
		t.Fatal("expected more payloads with WAF bypass")
	}
}

func TestFormatTimePayloads(t *testing.T) {
	payloads := FormatTimePayloads(5)
	if len(payloads) == 0 {
		t.Fatal("expected time payloads")
	}
	for _, p := range payloads {
		if p == "" {
			t.Fatal("empty payload")
		}
	}
}

func TestGetBooleanPairs(t *testing.T) {
	pairs := GetBooleanPairs()
	if len(pairs) == 0 {
		t.Fatal("expected boolean pairs")
	}
	for _, p := range pairs {
		if p.True == "" || p.False == "" {
			t.Fatal("empty pair")
		}
	}
}
