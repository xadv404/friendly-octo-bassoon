package benchmark

import (
	"testing"
)

func TestBenchmark_LocalVulnServer(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatalf("benchmark error: %v", err)
	}

	t.Logf("Benchmark: %d/%d passed, %d findings", result.Passed, result.Total, result.Findings)

	if result.Passed < result.Total {
		for _, f := range result.Failed {
			t.Error(f)
		}
	}

	// Au moins 6/7 vulns détectées (IDOR peut être capricieux)
	if result.Passed < 6 {
		t.Fatalf("trop d'échecs: %d/%d", result.Passed, result.Total)
	}
}
