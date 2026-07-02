package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sqli-hunter/sqli-hunter/internal/benchmark"
)

func main() {
	fmt.Println("═══ Benchmark sqli-hunter — scénarios réels ═══")
	fmt.Println()

	result, err := benchmark.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Résultat : %d/%d scénarios détectés\n\n", result.Passed, result.Total)

	// Par contexte
	contexts := make([]string, 0, len(result.ByContext))
	for ctx := range result.ByContext {
		contexts = append(contexts, ctx)
	}
	sort.Strings(contexts)

	fmt.Println("─── Par contexte applicatif ───")
	for _, ctx := range contexts {
		cr := result.ByContext[ctx]
		bar := strings.Repeat("█", cr.Passed) + strings.Repeat("░", cr.Total-cr.Passed)
		fmt.Printf("  %-20s %s %d/%d\n", ctx, bar, cr.Passed, cr.Total)
	}
	fmt.Println()

	// Détail scénarios
	fmt.Println("─── Détail des scénarios ───")
	for _, s := range result.Scenarios {
		icon := "✗"
		if s.Passed {
			icon = "✓"
		}
		fmt.Printf("  %s [%s|%s] %s\n", icon, s.Context, s.DBMS, s.Name)
		if !s.Passed {
			fmt.Printf("      attendu: %s | détecté: %s\n", s.Expected, s.Detected)
		}
	}

	if len(result.Failed) > 0 {
		fmt.Println("\n─── Échecs ───")
		for _, f := range result.Failed {
			fmt.Printf("  ✗ %s\n", f)
		}
	}

	if len(result.FalsePos) > 0 {
		fmt.Println("\n─── Faux positifs ───")
		for _, fp := range result.FalsePos {
			fmt.Printf("  ! %s\n", fp)
		}
	}

	fmt.Printf("\nFindings totaux : %d\n", result.Findings)

	if result.Passed < result.Total || len(result.FalsePos) > 0 {
		os.Exit(1)
	}
	fmt.Println("\n✓ Benchmark réussi")
}
