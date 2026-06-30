package main

import (
	"fmt"
	"os"

	"github.com/sqli-hunter/sqli-hunter/internal/benchmark"
)

func main() {
	fmt.Println("═══ Benchmark sqli-hunter — serveur vulnérable local ═══")
	fmt.Println()

	result, err := benchmark.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Résultat : %d/%d vulnérabilités détectées\n", result.Passed, result.Total)
	fmt.Printf("Findings totaux : %d\n\n", result.Findings)

	if len(result.Failed) > 0 {
		fmt.Println("Échecs :")
		for _, f := range result.Failed {
			fmt.Printf("  ✗ %s\n", f)
		}
		fmt.Println()
	}

	fmt.Println("Couverture OWASP Top 10:2025 (bug bounty automatisé) :")
	fmt.Println("  A01 Broken Access Control  → IDOR, LFI")
	fmt.Println("  A05 Injection              → SQLi, XSS, SSTI")
	fmt.Println("  A02 Security Misconfig       → SSRF (partiel)")
	fmt.Println("  Open Redirect              → classement fréquent bug bounty")

	if result.Passed < result.Total {
		os.Exit(1)
	}
	fmt.Println("\n✓ Benchmark réussi")
}
