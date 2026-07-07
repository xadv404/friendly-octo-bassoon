package main

import (
	"fmt"
	"os"

	"github.com/sqli-hunter/sqli-hunter/internal/discover"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
)

func runDorks(args []string) {
	out := discover.DefaultDorksPath("results")
	domain := "ch"
	subs := true
	set := discover.DorkSetBig

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-o", "--output":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "erreur: -o nécessite un fichier")
				os.Exit(1)
			}
			out = args[i]
		case "-d", "--domain":
			i++
			if i >= len(args) {
				fmt.Fprintln(os.Stderr, "erreur: -d nécessite un domaine")
				os.Exit(1)
			}
			domain = args[i]
		case "--no-subs":
			subs = false
		case "--vuln":
			set = discover.DorkSetVuln
		default:
			fmt.Fprintf(os.Stderr, "erreur: argument inconnu %q\n", args[i])
			os.Exit(1)
		}
	}

	n, err := discover.ExportDorksFile(out, domain, subs, set)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	printer := output.New(false, false)
	printer.Success(fmt.Sprintf("%d dorks → %s", n, out))
}
