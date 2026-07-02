package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/discover"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/runner"
	"github.com/sqli-hunter/sqli-hunter/internal/targets"
	"github.com/sqli-hunter/sqli-hunter/internal/urllist"
)

// executeScan lance le scan (-u ou -l) avec gestion des signaux.
func executeScan(ctx context.Context, cfg config, printer *output.Printer) error {
	opts := buildOptions(cfg)
	listDefaults := targets.Defaults{
		Method:  cfg.method,
		Headers: cfg.headers,
		Cookies: cfg.cookies,
		Params:  cfg.params,
		Data:    cfg.data,
		JSON:    cfg.jsonBody,
	}

	runCfg := runner.Config{
		Opts:           opts,
		OutputDir:      cfg.outputDir,
		UrlConcurrency: cfg.urlConcurrency,
		ProgressEvery:  cfg.progressEvery,
		ListDefaults:   listDefaults,
		Rescan:         cfg.rescan,
	}

	if cfg.listFile != "" {
		count, err := urllist.Count(cfg.listFile)
		if err != nil {
			return err
		}
		if count == 0 {
			return fmt.Errorf("liste vide")
		}
		applyMassDefaults(&runCfg, count, cfg.massMode)
		runCfg.ListFile = cfg.listFile
		runCfg.UrlCount = count

		printer.KV("mode", "mass scan (streaming)")
		printer.KV("targets", fmt.Sprintf("%d urls (%s)", count, cfg.listFile))
	} else {
		target, err := targets.FromURL(cfg.targetURL, listDefaults)
		if err != nil {
			return err
		}
		runCfg.Targets = []models.ScanTarget{target}
		printer.KV("target", truncate(target.URL, 70))
	}

	printer.ScanConfig(opts.Mode, opts.Categories, opts.IncludeWAF)
	printer.KV("threads", fmt.Sprintf("scan %d · extract %d · urls %d",
		opts.Threads, opts.ExtractThreads, runCfg.UrlConcurrency))
	printer.KV("rate", fmt.Sprintf("%d ms", opts.RateLimitMs))
	printer.KV("output", cfg.outputDir+"/emails/")
	printer.Rule()
	fmt.Println()

	r := &runner.Runner{Version: version, Printer: printer}
	_, err := r.Run(ctx, runCfg)
	return err
}

// runScanWithSignals exécute le scan avec annulation SIGINT/SIGTERM.
func runScanWithSignals(cfg config) {
	printer := output.New(cfg.noColor, cfg.verbose)
	if cfg.listFile != "" && cfg.targetURL == "" && cfg.discoverDomain == "" {
		// discover --scan ou -l : header déjà affiché
	} else if cfg.discoverDomain == "" {
		printer.Header(version)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		printer.Warning("interruption")
		cancel()
	}()

	if err := executeScan(ctx, cfg, printer); err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}
}

// discoverURLs collecte les URLs via Wayback et retourne le chemin du fichier scope.
func discoverURLs(ctx context.Context, cfg config, printer *output.Printer) (string, int, error) {
	printer.KV("discover", discoverLabel(cfg.discoverDomain))
	printer.KV("profil", "urls .ch vulnérables")
	if cfg.discoverPaths != "" {
		printer.KV("paths", cfg.discoverPaths)
	}
	if cfg.discoverParams != "" {
		printer.KV("params", cfg.discoverParams)
	}
	printer.KV("subs", fmt.Sprintf("%v", cfg.discoverSubs))
	printer.Rule()
	fmt.Println()

	opts := discover.Options{
		Domain:      cfg.discoverDomain,
		Output:      cfg.discoverOutput,
		Subs:        cfg.discoverSubs,
		Paths:       discover.ParseList(cfg.discoverPaths),
		Params:      discover.ParseList(cfg.discoverParams),
		NoFilter:    discoverNoFilter(cfg),
		Limit:       cfg.discoverLimit,
		Source:      discover.ParseSource(cfg.discoverSource),
		ResultsDir:  cfg.outputDir,
		SkipDumped:  !cfg.rescan,
		SkipScanned: cfg.skipScanned || discover.IsSwissWide(cfg.discoverDomain),
		AllowEmpty:  cfg.allowEmptyDiscover,
		OnProgress: func(fetched, kept, page int) {
			src := cfg.discoverSource
			if src == "" {
				src = "bing"
			}
			fmt.Fprintf(os.Stderr, "\r  %s page %d — %d urls lues, %d gardées", src, page+1, fetched, kept)
		},
	}

	result, err := discover.Run(ctx, opts)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", 0, err
	}

	printer.Success(fmt.Sprintf("%d URLs découvertes → %s", result.Kept, result.Output))
	if result.Skipped > 0 {
		printer.KV("ignorés", fmt.Sprintf("%d (déjà vus/dumpés)", result.Skipped))
	}
	printer.KV("lu", fmt.Sprintf("%d (%s)", result.Fetched, cfg.discoverSource))
	fmt.Println()

	return result.Output, result.Kept, nil
}

// discoverNoFilter : par défaut toutes les URLs .ch avec paramètres.
// --paths / --discover-params activent un filtre manuel ; --no-filter force tout garder.
func discoverNoFilter(cfg config) bool {
	if cfg.discoverNoFilter {
		return true
	}
	if cfg.discoverPaths != "" || cfg.discoverParams != "" {
		return false
	}
	return true
}

func discoverLabel(domain string) string {
	if discover.IsSwissWide(domain) || discover.NormalizeSwissDomain(domain) == "ch" {
		return "URLs vulnérables .ch (Bing dorks)"
	}
	return discover.NormalizeSwissDomain(domain)
}
