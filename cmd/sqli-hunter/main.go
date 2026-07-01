package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"encoding/json"
	"strconv"
	"strings"
	"syscall"

	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/runner"
	"github.com/sqli-hunter/sqli-hunter/internal/targets"
	"github.com/sqli-hunter/sqli-hunter/internal/urllist"
)

const version = "1.9.2"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "discover":
			runDiscover(os.Args[2:])
			return
		case "-h", "--help":
			printUsage()
			return
		}
	}

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur: %v\n", err)
		os.Exit(1)
	}

	if cfg.showHelp {
		printUsage()
		return
	}
	if cfg.showVersion {
		fmt.Printf("sqli-hunter %s\n", version)
		return
	}

	if cfg.targetURL == "" && cfg.listFile == "" {
		fmt.Fprintln(os.Stderr, "erreur: -u ou -l requis")
		os.Exit(1)
	}

	printer := output.New(cfg.noColor, cfg.verbose)
	printer.Header(version)

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
	}

	if cfg.listFile != "" {
		count, err := urllist.Count(cfg.listFile)
		if err != nil {
			printer.Error(err.Error())
			os.Exit(1)
		}
		if count == 0 {
			printer.Error("liste vide")
			os.Exit(1)
		}
		applyMassDefaults(&runCfg, count, cfg.massMode)
		runCfg.ListFile = cfg.listFile
		runCfg.UrlCount = count

		printer.KV("mode", "mass scan (streaming)")
		printer.KV("targets", fmt.Sprintf("%d urls (%s)", count, cfg.listFile))
	} else {
		target, err := targets.FromURL(cfg.targetURL, listDefaults)
		if err != nil {
			printer.Error(err.Error())
			os.Exit(1)
		}
		runCfg.Targets = []models.ScanTarget{target}
		printer.KV("target", truncate(target.URL, 70))
	}

	printer.ScanConfig(opts.Mode, opts.Categories, opts.IncludeWAF)
	printer.KV("threads", fmt.Sprintf("scan %d · extract %d · urls %d",
		opts.Threads, opts.ExtractThreads, runCfg.UrlConcurrency))
	printer.KV("rate", fmt.Sprintf("%d ms", opts.RateLimitMs))
	printer.KV("output", cfg.outputDir+"/DOMAIN/DOMAIN.{json,sql}")
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

	r := &runner.Runner{Version: version, Printer: printer}
	if _, err := r.Run(ctx, runCfg); err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}
}

func applyMassDefaults(cfg *runner.Config, urlCount int, forceMass bool) {
	mass := forceMass || urlCount >= 500
	if !mass {
		return
	}
	if cfg.UrlConcurrency <= 4 {
		cfg.UrlConcurrency = 32
	}
	if cfg.ProgressEvery <= 0 {
		cfg.ProgressEvery = 100
	}
	if urlCount >= 10000 && cfg.UrlConcurrency < 64 {
		cfg.UrlConcurrency = 64
	}
}

type config struct {
	targetURL      string
	listFile       string
	outputDir      string
	method         string
	params         map[string]string
	data           map[string]string
	headers        map[string]string
	cookies        map[string]string
	jsonBody       map[string]any
	categories     []models.VulnCategory
	techniques     []models.VulnType
	customPayloads []string
	fullScan       bool
	includeWAF     bool
	timeDelay      int
	timeThreshold  float64
	rateLimit      int
	timeout        int
	threads        int
	extractThreads int
	urlConcurrency int
	progressEvery  int
	massMode       bool
	extractMeta    bool
	verbose        bool
	noColor        bool
	showHelp       bool
	showVersion    bool
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		method:         "GET",
		timeDelay:      3,
		timeout:        15,
		threads:        8,
		extractThreads: 2,
		urlConcurrency: 4,
		rateLimit:      100,
		outputDir:      "results",
		params:         make(map[string]string),
		data:           make(map[string]string),
		headers:        make(map[string]string),
		cookies:        make(map[string]string),
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help":
			cfg.showHelp = true
		case arg == "--version":
			cfg.showVersion = true
		case arg == "-u" || arg == "--url":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-u nécessite une valeur")
			}
			cfg.targetURL = args[i]
		case arg == "-l" || arg == "--list":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-l nécessite un fichier")
			}
			cfg.listFile = args[i]
		case arg == "-o" || arg == "--output":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-o nécessite un répertoire")
			}
			cfg.outputDir = args[i]
		case arg == "-m" || arg == "--method":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-m nécessite une valeur")
			}
			cfg.method = strings.ToUpper(args[i])
		case arg == "-p" || arg == "--param":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-p nécessite une valeur")
			}
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format param : nom=valeur")
			}
			cfg.params[parts[0]] = parts[1]
		case arg == "-d" || arg == "--data":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-d nécessite une valeur")
			}
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format data : nom=valeur")
			}
			cfg.data[parts[0]] = parts[1]
		case arg == "--json":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--json nécessite un corps JSON")
			}
			if err := json.Unmarshal([]byte(args[i]), &cfg.jsonBody); err != nil {
				return cfg, fmt.Errorf("JSON invalide : %w", err)
			}
		case arg == "-H" || arg == "--header":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-H nécessite une valeur")
			}
			parts := strings.SplitN(args[i], ":", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format header : Nom: Valeur")
			}
			cfg.headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		case arg == "-c" || arg == "--cookie":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-c nécessite une valeur")
			}
			parts := strings.SplitN(args[i], "=", 2)
			if len(parts) != 2 {
				return cfg, fmt.Errorf("format cookie : nom=valeur")
			}
			cfg.cookies[parts[0]] = parts[1]
		case arg == "-t" || arg == "--test":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("-t nécessite une valeur")
			}
			for _, t := range strings.Split(args[i], ",") {
				cat, tech, err := payloads.ParseCategory(strings.TrimSpace(t))
				if err != nil {
					return cfg, err
				}
				cfg.categories = appendUniqueCategory(cfg.categories, cat)
				if tech != "" {
					cfg.techniques = append(cfg.techniques, tech)
				}
			}
		case arg == "--payload":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--payload nécessite une valeur")
			}
			cfg.customPayloads = append(cfg.customPayloads, args[i])
		case arg == "--full":
			cfg.fullScan = true
		case arg == "--waf":
			cfg.includeWAF = true
		case arg == "--time-delay":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--time-delay nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--time-delay doit être >= 1")
			}
			cfg.timeDelay = v
		case arg == "--time-threshold":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--time-threshold nécessite une valeur")
			}
			v, err := strconv.ParseFloat(args[i], 64)
			if err != nil {
				return cfg, fmt.Errorf("--time-threshold invalide")
			}
			cfg.timeThreshold = v
		case arg == "--rate-limit":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--rate-limit nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("--rate-limit invalide")
			}
			cfg.rateLimit = v
		case arg == "--timeout":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--timeout nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil {
				return cfg, fmt.Errorf("--timeout invalide")
			}
			cfg.timeout = v
		case arg == "--threads":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--threads nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--threads doit être >= 1")
			}
			cfg.threads = v
		case arg == "--extract-threads":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--extract-threads nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--extract-threads doit être >= 1")
			}
			cfg.extractThreads = v
		case arg == "--url-threads":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--url-threads nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--url-threads doit être >= 1")
			}
			cfg.urlConcurrency = v
		case arg == "--progress-every":
			i++
			if i >= len(args) {
				return cfg, fmt.Errorf("--progress-every nécessite une valeur")
			}
			v, err := strconv.Atoi(args[i])
			if err != nil || v < 1 {
				return cfg, fmt.Errorf("--progress-every doit être >= 1")
			}
			cfg.progressEvery = v
		case arg == "--mass":
			cfg.massMode = true
		case arg == "--extract-meta":
			cfg.extractMeta = true
		case arg == "-v" || arg == "--verbose":
			cfg.verbose = true
		case arg == "--no-color":
			cfg.noColor = true
		default:
			return cfg, fmt.Errorf("argument inconnu : %s", arg)
		}
	}

	return cfg, nil
}

func appendUniqueCategory(cats []models.VulnCategory, cat models.VulnCategory) []models.VulnCategory {
	for _, c := range cats {
		if c == cat {
			return cats
		}
	}
	return append(cats, cat)
}

func buildOptions(cfg config) models.ScanOptions {
	mode := models.ScanFast
	if cfg.fullScan {
		mode = models.ScanFull
	}
	categories := cfg.categories
	if len(categories) == 0 {
		categories = payloads.DefaultCategories(mode)
	}
	return models.ScanOptions{
		Categories:      categories,
		Techniques:      cfg.techniques,
		Mode:            mode,
		IncludeWAF:      cfg.includeWAF,
		CustomPayloads:  cfg.customPayloads,
		TimeDelaySec:    cfg.timeDelay,
		TimeThresholdMs: cfg.timeThreshold,
		RateLimitMs:     cfg.rateLimit,
		TimeoutSec:      cfg.timeout,
		Threads:         cfg.threads,
		ExtractThreads:  cfg.extractThreads,
		Verbose:         cfg.verbose,
		EarlyExit:       true,
		PIIOnly:         !cfg.extractMeta,
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func printUsage() {
	fmt.Print(`sqli-hunter — détection d'injections base de données

Usage:
  sqli-hunter -u <URL> [options]
  sqli-hunter -l <fichier> [options]
  sqli-hunter discover -d <domaine> [options]

Découverte d'URLs (Wayback):
  sqli-hunter discover -d assureur.com --preset insurance
  sqli-hunter discover -d target.com --no-filter -o scope.txt

Cible:
  -u, --url <URL>             URL unique avec paramètres
  -l, --list <fichier>        Fichier d'URLs (une par ligne, # commentaires)
  -o, --output <dir>          Répertoire de sortie [défaut: results]
                              → results/SITE.COM/SITE.COM.json
                              → results/SITE.COM/SITE.COM.sql
  -m, --method <METHOD>       GET ou POST [défaut: GET]
  -p, --param <nom=valeur>    Paramètre GET additionnel (mode -u)
  -d, --data <nom=valeur>     Paramètre POST (mode -u)
      --json <JSON>           Corps JSON (mode -u)

Requête:
  -H, --header <Nom: Val>     Header HTTP (répétable)
  -c, --cookie <nom=val>      Cookie (répétable)

Injections:
  -t, --test <liste>          sqli,nosql,error,union,boolean,time
      --full                  Scan complet (+ time-based)
      --waf                   Payloads bypass WAF
      --payload <PAYLOAD>       Payload personnalisé

Performance:
      --threads <n>           Workers scan par URL [défaut: 8]
      --extract-threads <n>     Workers extraction [défaut: 2]
      --extract-meta            Extraire métadonnées DB (version, tables…) au lieu des PII
      --url-threads <n>         URLs en parallèle [défaut: 4, auto 32+ en mass]
      --progress-every <n>      Progression tous les N URLs [défaut: 100]
      --mass                    Force mode massif (streaming, dès 500 URLs auto)
      --rate-limit <ms>       Délai entre requêtes [défaut: 100]
      --timeout <sec>         Timeout HTTP [défaut: 15]

Affichage:
  -v, --verbose               Détails payloads et preuves
      --no-color              Sans couleurs
  -h, --help
      --version

Exemples:
  sqli-hunter -u "https://target.com/page?id=1"
  sqli-hunter -l urls.txt --url-threads 64
  sqli-hunter -l scope_50k.txt --mass --progress-every 500

`)
}
