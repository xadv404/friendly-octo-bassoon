package benchmark

import (
	"fmt"
	"strings"
	"testing"
)

func TestBenchmark_AllRealWorldScenarios(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatalf("benchmark error: %v", err)
	}

	t.Logf("═══ Résultat global : %d/%d scénarios ═══", result.Passed, result.Total)

	for ctx, cr := range result.ByContext {
		t.Logf("  [%s] %d/%d", ctx, cr.Passed, cr.Total)
	}

	for _, s := range result.Scenarios {
		status := "✗"
		if s.Passed {
			status = "✓"
		}
		t.Logf("  %s [%s|%s] %s", status, s.Context, s.DBMS, s.Name)
	}

	if len(result.Failed) > 0 {
		for _, f := range result.Failed {
			t.Error(f)
		}
	}

	if len(result.FalsePos) > 0 {
		for _, fp := range result.FalsePos {
			t.Error("faux positif: " + fp)
		}
	}

	// Au moins 90% des scénarios vulnérables détectés
	minPass := int(float64(result.Total) * 0.9)
	if result.Passed < minPass {
		t.Fatalf("seulement %d/%d passés (minimum %d)", result.Passed, result.Total, minPass)
	}
}

func TestBenchmark_EcommerceContext(t *testing.T) {
	result := runContext(t, "e-commerce")
	if result.Passed < result.Total {
		t.Fatalf("e-commerce: %d/%d", result.Passed, result.Total)
	}
}

func TestBenchmark_AuthContext(t *testing.T) {
	result := runContext(t, "authentification")
	if result.Passed < result.Total {
		t.Fatalf("auth: %d/%d", result.Passed, result.Total)
	}
}

func TestBenchmark_APIContext(t *testing.T) {
	result := runContext(t, "api-rest")
	if result.Passed < result.Total {
		t.Fatalf("api: %d/%d", result.Passed, result.Total)
	}
}

func TestBenchmark_AdminContext(t *testing.T) {
	result := runContext(t, "panel-admin")
	if result.Passed < result.Total {
		t.Fatalf("admin: %d/%d", result.Passed, result.Total)
	}
}

func TestBenchmark_HealthcareContext(t *testing.T) {
	result := runContext(t, "santé")
	if result.Passed < result.Total {
		t.Fatalf("santé: %d/%d", result.Passed, result.Total)
	}
}

func TestBenchmark_BankingContext(t *testing.T) {
	result := runContext(t, "banque")
	if result.Passed < result.Total {
		t.Fatalf("banque: %d/%d", result.Passed, result.Total)
	}
}

func TestBenchmark_NoFalsePositives(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	if len(result.FalsePos) > 0 {
		t.Fatalf("%d faux positifs: %s", len(result.FalsePos), strings.Join(result.FalsePos, "; "))
	}
}

func runContext(t *testing.T, ctx string) ContextResult {
	t.Helper()
	result, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	cr, ok := result.ByContext[ctx]
	if !ok {
		t.Fatalf("contexte %s non trouvé", ctx)
	}
	return cr
}

func TestBenchmark_ScenarioCount(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatal(err)
	}
	if result.Total < 20 {
		t.Fatalf("attendu >= 20 scénarios, got %d", result.Total)
	}
	t.Logf("%d scénarios réalistes testés", result.Total)
}

// Test détaillé par DBMS
func TestBenchmark_AllDBMS(t *testing.T) {
	result, err := Run()
	if err != nil {
		t.Fatal(err)
	}

	dbmsCount := map[string]int{}
	dbmsPass := map[string]int{}
	for _, s := range result.Scenarios {
		dbmsCount[s.DBMS]++
		if s.Passed {
			dbmsPass[s.DBMS]++
		}
	}

	for dbms, total := range dbmsCount {
		passed := dbmsPass[dbms]
		t.Logf("  DBMS %s: %d/%d", dbms, passed, total)
		if passed < total {
			t.Errorf("DBMS %s: %d/%d échecs", dbms, total-passed, total)
		}
	}
}

func ExampleRun() {
	result, _ := Run()
	fmt.Printf("%d/%d\n", result.Passed, result.Total)
}
