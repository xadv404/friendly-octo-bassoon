package payloads

import (
	"testing"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
)

func TestBuildJobs_FastMode(t *testing.T) {
	opts := models.ScanOptions{Mode: models.ScanFast}
	jobs := BuildJobs(opts)
	if len(jobs) == 0 {
		t.Fatal("expected jobs")
	}

	hasSQLi, hasNoSQL, hasTime := false, false, false
	for _, j := range jobs {
		if j.Category == models.CategorySQLi {
			hasSQLi = true
		}
		if j.VulnType == models.NoSQL {
			hasNoSQL = true
		}
		if j.VulnType == models.SQLiTime {
			hasTime = true
		}
	}
	if !hasSQLi || !hasNoSQL {
		t.Fatal("fast mode should include sqli and nosql")
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

func TestUnionPayloads_DBExtraction(t *testing.T) {
	payloads := unionPayloads(false)
	found := false
	for _, p := range payloads {
		if contains(p, "version") || contains(p, "database") || contains(p, "information_schema") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("union payloads should target DB extraction")
	}
}

func TestParseCategory(t *testing.T) {
	cat, _, err := ParseCategory("nosql")
	if err != nil || cat != models.CategoryNoSQL {
		t.Fatal("expected nosql")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
