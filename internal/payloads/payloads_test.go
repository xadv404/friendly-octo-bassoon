package payloads

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestBuildJobs_FastMode(t *testing.T) {
	opts := models.ScanOptions{Mode: models.ScanFast}
	jobs := BuildJobs(opts)
	if len(jobs) == 0 {
		t.Fatal("expected jobs in fast mode")
	}

	hasXSS, hasSQLi, hasTime := false, false, false
	for _, j := range jobs {
		if j.VulnType == models.XSS {
			hasXSS = true
		}
		if j.Category == models.CategorySQLi {
			hasSQLi = true
		}
		if j.VulnType == models.SQLiTime {
			hasTime = true
		}
	}
	if !hasXSS || !hasSQLi {
		t.Fatal("fast mode should include sqli and xss")
	}
	if hasTime {
		t.Fatal("fast mode should not include time-based")
	}
}

func TestBuildJobs_FullMode(t *testing.T) {
	opts := models.ScanOptions{Mode: models.ScanFull, Categories: []models.VulnCategory{models.CategorySQLi}}
	jobs := BuildJobs(opts)
	hasTime := false
	for _, j := range jobs {
		if j.VulnType == models.SQLiTime {
			hasTime = true
		}
	}
	if !hasTime {
		t.Fatal("full mode should include time-based")
	}
}

func TestFastPayloadsSmallerThanFull(t *testing.T) {
	fast := BuildJobs(models.ScanOptions{Mode: models.ScanFast})
	full := BuildJobs(models.ScanOptions{Mode: models.ScanFull})
	if len(fast) >= len(full) {
		t.Fatalf("fast (%d) should have fewer jobs than full (%d)", len(fast), len(full))
	}
}

func TestGetBooleanPairs(t *testing.T) {
	pairs := GetBooleanPairs(false)
	if len(pairs) == 0 {
		t.Fatal("expected boolean pairs")
	}
}

func TestParseCategory(t *testing.T) {
	cat, _, err := ParseCategory("sqli")
	if err != nil || cat != models.CategorySQLi {
		t.Fatal("expected sqli category")
	}
	cat, tech, err := ParseCategory("xss")
	if err != nil || cat != models.CategoryXSS || tech != models.XSS {
		t.Fatal("expected xss")
	}
}

func TestDefaultSQLiTechniques_FastNoTime(t *testing.T) {
	techs := DefaultSQLiTechniques(models.ScanFast)
	for _, tech := range techs {
		if tech == models.SQLiTime {
			t.Fatal("fast should not include time")
		}
	}
}
