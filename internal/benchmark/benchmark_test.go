package benchmark

import (
	"testing"
)

func TestBenchmark_LocalDBVulns(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatalf("benchmark error: %v", err)
	}

	t.Logf("Benchmark DB: %d/%d passed", result.Passed, result.Total)

	if result.Passed < result.Total {
		for _, f := range result.Failed {
			t.Error(f)
		}
	}
}
