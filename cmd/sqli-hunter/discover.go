package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/sqli-hunter/sqli-hunter/internal/discover"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
)

type discoverConfig struct {
	domain     string
	output     string
	paths      string
	params     string
	subs       bool
	noFilter   bool
	limit      int
	source     string
	rescan     bool
	resultsDir string
	scan       bool
	scanExtra  []string
	help       bool
}

func runDiscover(args []string) {
	cfg, err := parseDiscoverArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}
	if cfg.help {
		printDiscoverUsage()
		return
	}
	if cfg.domain == "" {
		fmt.Fprintln(os.Stderr, "erreur: -d requis")
		printDiscoverUsage()
		os.Exit(1)
	}

	printer := output.New(false, false)
	printer.Header(version)
	printer.KV("commande", "discover")
	printer.KV("domaine", discoverLabel(cfg.domain))
	printer.KV("profil", "urls .ch avec paramètres")
	if cfg.paths != "" {
		printer.KV("paths", cfg.paths)
	}
	if cfg.params != "" {
		printer.KV("params", cfg.params)
	}
	printer.KV("subs", fmt.Sprintf("%v", cfg.subs))
	printer.Rule()
	fmt.Println()

	ctx := context.Background()
	opts := discover.Options{
		Domain:     cfg.domain,
		Output:     cfg.output,
		Subs:       cfg.subs,
		Paths:      discover.ParseList(cfg.paths),
		Params:     discover.ParseList(cfg.params),
		NoFilter:   discoverNoFilterDiscover(cfg),
		Limit:      cfg.limit,
		Source:     discover.ParseSource(cfg.source),
		ResultsDir: cfg.resultsDir,
		SkipDumped: !cfg.rescan,
		OnProgress: func(fetched, kept, page int) {
			src := cfg.source
			if src == "" {
				src = "google"
			}
			fmt.Fprintf(os.Stderr, "\r  %s page %d — %d urls lues, %d gardées", src, page+1, fetched, kept)
		},
	}

	result, err := discover.Run(ctx, opts)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}

	printer.Success(fmt.Sprintf("%d URLs → %s", result.Kept, result.Output))
	printer.KV("lu", fmt.Sprintf("%d (%s)", result.Fetched, cfg.source))
	fmt.Println()
	fmt.Printf("  sqli-hunter -l %s --url-threads 64\n", result.Output)

	if cfg.scan {
		fmt.Println()
		printer.KV("mode", "scan auto")
		scanArgs := []string{"-l", result.Output, "--url-threads", "64"}
		scanArgs = append(scanArgs, cfg.scanExtra...)
		scanCfg, err := parseArgs(scanArgs)
		if err != nil {
			printer.Error(err.Error())
			os.Exit(1)
		}
		runScanWithSignals(scanCfg)
	}
}

func parseDiscoverArgs(args []string) (discoverConfig, error) {
	cfg := discoverConfig{subs: true, source: "google", resultsDir: "results"}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			cfg.help = true
		case arg == "-d" || arg == "--domain":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-d nécessite un domaine")
			}
			cfg.domain = args[i]
		case arg == "-o" || arg == "--output":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-o nécessite un fichier")
			}
			cfg.output = args[i]
		case arg == "--paths":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--paths nécessite une valeur")
			}
			cfg.paths = args[i]
		case arg == "--params":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--params nécessite une valeur")
			}
			cfg.params = args[i]
		case arg == "--subs":
			cfg.subs = true
		case arg == "--no-subs":
			cfg.subs = false
		case arg == "--no-filter":
			cfg.noFilter = true
		case arg == "--limit":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--limit nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--limit doit être >= 1")
			}
			cfg.limit = v
		case arg == "--source":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--source nécessite google ou wayback")
			}
			cfg.source = args[i]
		case arg == "--rescan":
			cfg.rescan = true
		case arg == "--results-dir":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--results-dir nécessite un chemin")
			}
			cfg.resultsDir = args[i]
		case arg == "--scan":
			cfg.scan = true
			// Arguments après -- sont transmis au scan
			if i+1 < len(args) && args[i+1] == "--" {
				cfg.scanExtra = args[i+2:]
				i = len(args)
			}
		default:
			return cfg, fmt.Errorf("argument inconnu : %s", arg)
		}
	}
	return cfg, nil
}

func discoverNoFilterDiscover(cfg discoverConfig) bool {
	if cfg.noFilter {
		return true
	}
	if cfg.paths != "" || cfg.params != "" {
		return false
	}
	return true
}

func printDiscoverUsage() {
	fmt.Print(`sqli-hunter discover — URLs suisses (.ch) via Google (proxy BP)

Usage:
  sqli-hunter discover -d <domaine.ch> [options]

Source:
  --source <google|wayback>   Collecteur [défaut: google]
  -d, --domain <ch|domaine.ch>  ch = URLs vuln .ch · ou un domaine pour wayback
      --subs                  Inclure sous-domaines [défaut: oui]
      --no-subs               Domaine exact uniquement
      --rescan                Inclure domaines déjà dumpés

Filtres (optionnels) :
      --paths <a,b,c>         Mots-clés dans le path/URL
      --params <a,b,c>        Noms de paramètres query
      --no-filter             Toutes URLs .ch avec ?key=val

Sortie:
  -o, --output <fichier>      Fichier scope [défaut: scope_DOMAIN.ch.txt]
      --limit <n>             Max URLs à garder
      --results-dir <dir>     Dossier results [défaut: results]
      --scan                  Lancer le scan SQLi après découverte

Exemples:
  sqli-hunter discover -d ch --limit 500
  sqli-hunter discover -d shop.ch --source wayback --limit 1000

`)
}
