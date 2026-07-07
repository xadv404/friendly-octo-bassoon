package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/notify"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
	"github.com/sqli-hunter/sqli-hunter/internal/urllist"
)

const huntScopeFile = "scope_hunt.txt"

// runHunt scanne les URLs de scope_hunt.txt (dorks manuels, pas de discover auto).
func runHunt(args []string) {
	cfg, err := parseHuntArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	scopePath := cfg.listFile
	if scopePath == "" {
		scopePath = filepath.Join(cfg.outputDir, huntScopeFile)
		cfg.listFile = scopePath
	}

	count, err := urllist.Count(scopePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "erreur: fichier scope introuvable — %s\n", scopePath)
			fmt.Fprintln(os.Stderr, "  1. sqli-hunter dorks -o results/dorks_ch.txt")
			fmt.Fprintln(os.Stderr, "  2. lance les dorks sur Google, colle les URLs dans scope_hunt.txt")
			fmt.Fprintln(os.Stderr, "  3. sqli-hunter hunt")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}
	if count == 0 {
		fmt.Fprintf(os.Stderr, "erreur: %s est vide — ajoute des URLs\n", scopePath)
		os.Exit(1)
	}

	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)
	printer.KV("mode", "hunt — scan seulement (.ch)")
	printer.KV("scope", fmt.Sprintf("%d URLs · %s", count, scopePath))
	printer.KV("threads", fmt.Sprintf("scan %d · urls %d · extract %d", cfg.threads, cfg.urlConcurrency, cfg.extractThreads))
	printer.KV("scan", "full + waf + rescan")
	printer.KV("output", cfg.outputDir+"/emails/")
	printer.Rule()
	fmt.Println()

	n := notify.Default()
	_ = results.WriteRunStatus(cfg.outputDir, results.RunStatus{Phase: "scan", ScanTotal: count})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		printer.Warning("interruption")
		cancel()
	}()

	cfg.skipScanned = false
	cfg.rescan = true
	applyMassDefaultsToConfig(&cfg, count)
	cfg.massMode = true
	if cfg.progressEvery <= 0 {
		cfg.progressEvery = 200
	}

	if err := executeScan(ctx, cfg, printer); err != nil {
		if n.Enabled() && !errors.Is(err, context.Canceled) {
			n.Error("Scan hunt: " + err.Error())
		}
		printer.Error(err.Error())
		os.Exit(1)
	}

	printEmailStock(printer, cfg.outputDir)
}

func printEmailStock(printer *output.Printer, outputDir string) {
	list, err := results.ListProviders(outputDir)
	if err != nil || len(list) == 0 {
		return
	}
	printer.Rule()
	fmt.Println()
	printer.KV("stock emails", "")
	for _, p := range list {
		fmt.Printf("  • %s — %d\n", p.Provider, p.Count)
	}
}

func parseHuntArgs(args []string) (config, error) {
	scanArgs := append([]string{
		"--mass", "--full", "--waf", "--rescan",
		"-t", "sqli,error,union,boolean,time",
		"--url-threads", "96",
		"--threads", "12",
		"--extract-threads", "6",
		"--progress-every", "200",
	}, args...)
	return parseArgs(scanArgs)
}
