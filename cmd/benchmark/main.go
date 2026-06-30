package main

import (
	"fmt"
	"os"

	"github.com/sqli-hunter/sqli-hunter/internal/benchmark"
)

func main() {
	fmt.Println("═══ Benchmark sqli-hunter — injections base de données ═══")
	fmt.Println()

	result, err := benchmark.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Résultat : %d/%d injections DB détectées\n\n", result.Passed, result.Total)

	if len(result.Failed) > 0 {
		fmt.Println("Échecs :")
		for _, f := range result.Failed {
			fmt.Printf("  ✗ %s\n", f)
		}
		fmt.Println()
	}

	fmt.Println("Scénarios testés :")
	fmt.Println("  • SQLi error-based")
	fmt.Println("  • SQLi union (extraction version MySQL)")
	fmt.Println("  • SQLi boolean blind")
	fmt.Println("  • NoSQL injection (bypass auth MongoDB)")

	if result.Passed < result.Total {
		os.Exit(1)
	}
	fmt.Println("\n✓ Benchmark réussi")
}
