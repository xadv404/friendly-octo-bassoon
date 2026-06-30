package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sqli-hunter/sqli-hunter/internal/client"
	"github.com/sqli-hunter/sqli-hunter/internal/extractor"
	"github.com/sqli-hunter/sqli-hunter/internal/models"
	"github.com/sqli-hunter/sqli-hunter/internal/output"
	"github.com/sqli-hunter/sqli-hunter/internal/payloads"
	"github.com/sqli-hunter/sqli-hunter/internal/scanner"
)

const version = "1.3.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cfg, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Erreur: %v\n", err)
		os.Exit(1)
	}

	if cfg.showHelp {
		printUsage()
		return
	}
	if cfg.showVersion {
		fmt.Printf("sqli-hunter v%s\n", version)
		return
	}

	printer := output.NewPrinter(cfg.noColor)
	printer.Banner()

	if cfg.targetURL == "" {
		printer.Error("URL requise (-u)")
		os.Exit(1)
	}

	target, err := buildTarget(cfg)
	if err != nil {
		printer.Error(err.Error())
		os.Exit(1)
	}

	opts := buildOptions(cfg)
	printer.Info(fmt.Sprintf("Cible : %s", cfg.targetURL))
	printer.Info(fmt.Sprintf("Méthode : %s", target.Method))
	if !opts.ExtractOnly {
		printer.PrintScanConfig(opts.Mode, opts.Categories, opts.IncludeWAF)
	}
	if opts.AutoExtract {
		printer.PrintExtractMode("automatique (dès détection)")
	} else if opts.ExtractAfter {
		printer.PrintExtractMode("après scan")
	} else if opts.ExtractOnly {
		printer.PrintExtractMode("extraction seule")
	}
	printer.Info(fmt.Sprintf("Threads : %d | Timeout : %ds | Rate limit : %dms", opts.Threads, opts.TimeoutSec, opts.RateLimitMs))
	fmt.Println()

	httpClient := client.New(opts.TimeoutSec, target.Headers, target.Cookies)
	rateLimit := func() {
		if opts.RateLimitMs > 0 {
			time.Sleep(time.Duration(opts.RateLimitMs) * time.Millisecond)
		}
	}

	var allExtractions []models.ExtractedData
	ext := extractor.New(httpClient,
		func(d models.ExtractedData) {
			allExtractions = append(allExtractions, d)
			printer.Extraction(d)
		},
		func(msg string) {
			if opts.Verbose {
				printer.Verbose(msg)
			}
		},
		rateLimit,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		printer.Warning("Interruption — arrêt en cours...")
		cancel()
	}()

	start := time.Now()

	// Mode extraction seule : pas de scan de détection
	if opts.ExtractOnly {
		printer.Info("Mode extraction — tentative directe sur les paramètres")
		ext.ExtractDirect(ctx, target)
		printer.ExtractionSummary(allExtractions)
		printer.Info(fmt.Sprintf("Durée : %s", time.Since(start).Round(time.Millisecond)))
		if len(allExtractions) == 0 {
			printer.Warning("Aucune donnée extraite — lancez d'abord un scan ou vérifiez l'injection")
		}
		return
	}

	// Callback extraction auto dès détection
	onFinding := func(f models.Finding) {
		printer.Finding(f)
		if opts.AutoExtract {
			ext.ExtractFromFinding(ctx, target, f)
		}
	}

	sc := scanner.New(httpClient, opts, onFinding,
		func(msg string) { printer.Verbose(msg) },
	)

	result := sc.Scan(ctx, target)

	// Phase 2 : extraction après scan
	if opts.ExtractAfter && len(result.Findings) > 0 {
		fmt.Println()
		printer.Info(fmt.Sprintf("Phase extraction — %d vulnérabilité(s) à exploiter", len(result.Findings)))
		extResult := ext.ExtractAll(ctx, target, result.Findings)
		for _, d := range extResult.Extractions {
			if !containsExtraction(allExtractions, d) {
				allExtractions = append(allExtractions, d)
			}
		}
	}

	result.Extractions = allExtractions
	elapsed := time.Since(start)

	printer.Summary(result)
	printer.ExtractionSummary(allExtractions)
	printer.Info(fmt.Sprintf("Durée : %s", elapsed.Round(time.Millisecond)))
}

type config struct {
	targetURL      string
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
	verbose        bool
	noColor        bool
	autoExtract    bool
	extractOnly    bool
	extractAfter   bool
	showHelp       bool
	showVersion    bool
}

func parseArgs(args []string) (config, error) {
	cfg := config{
		method:    "GET",
		timeDelay: 3,
		timeout:   15,
		threads:   8,
		rateLimit: 100,
		params:    make(map[string]string),
		data:      make(map[string]string),
		headers:   make(map[string]string),
		cookies:   make(map[string]string),
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
		case arg == "-v" || arg == "--verbose":
			cfg.verbose = true
		case arg == "--no-color":
			cfg.noColor = true
		case arg == "--auto-extract":
			cfg.autoExtract = true
		case arg == "--extract":
			cfg.extractOnly = true
		case arg == "--extract-after":
			cfg.extractAfter = true
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

func containsExtraction(list []models.ExtractedData, d models.ExtractedData) bool {
	for _, e := range list {
		if e.Parameter == d.Parameter && e.DataType == d.DataType && e.Value == d.Value {
			return true
		}
	}
	return false
}

func buildTarget(cfg config) (models.ScanTarget, error) {
	u, err := url.Parse(cfg.targetURL)
	if err != nil {
		return models.ScanTarget{}, fmt.Errorf("URL invalide : %w", err)
	}

	if len(cfg.params) == 0 && u.RawQuery != "" {
		for k, vals := range u.Query() {
			if len(vals) > 0 {
				cfg.params[k] = vals[0]
			}
		}
	}

	if len(cfg.params) == 0 && len(cfg.data) == 0 && cfg.jsonBody == nil {
		return models.ScanTarget{}, fmt.Errorf("aucun paramètre — utilisez -p, -d ou --json")
	}

	method := cfg.method
	if len(cfg.data) > 0 || cfg.jsonBody != nil {
		if method == "GET" {
			method = "POST"
		}
	}

	return models.ScanTarget{
		URL: cfg.targetURL, Method: method,
		Params: cfg.params, Data: cfg.data,
		Headers: cfg.headers, Cookies: cfg.cookies,
		JSONBody: cfg.jsonBody,
	}, nil
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
		Verbose:         cfg.verbose,
		EarlyExit:       !cfg.extractAfter,
		AutoExtract:     cfg.autoExtract,
		ExtractOnly:     cfg.extractOnly,
		ExtractAfter:    cfg.extractAfter,
	}
}

func printUsage() {
	fmt.Print(`sqli-hunter — Détection d'injections base de données pour bug bounty

Usage:
  sqli-hunter -u <URL> [options]

Cible:
  -u, --url <URL>           URL cible (requise)
  -m, --method <METHOD>     Méthode HTTP (GET, POST) [défaut: GET]
  -p, --param <nom=valeur>  Paramètre GET (répétable)
  -d, --data <nom=valeur>   Paramètre POST form (répétable)
      --json <JSON>         Corps JSON (ex: '{"id":1}')

Requête:
  -H, --header <Nom: Val>   Header HTTP (répétable)
  -c, --cookie <nom=val>    Cookie (répétable)

Injections DB:
  -t, --test <liste>        sqli,nosql,error,union,boolean,time [défaut: sqli,nosql]
      --full                Scan complet (+ time-based SQLi)
      --waf                 Payloads bypass WAF
      --payload <PAYLOAD>   Payload SQLi personnalisé (répétable)

Extraction:
      --auto-extract        Extraire dès qu'une vuln est détectée
      --extract-after       Scanner puis extraire sur toutes les vulns
      --extract             Mode extraction seul (URL déjà vulnérable)

Timing:
      --time-delay <sec>    Délai time-based [défaut: 3]
      --rate-limit <ms>     Délai entre requêtes [défaut: 100]
      --timeout <sec>       Timeout HTTP [défaut: 15]
      --threads <n>         Goroutines [défaut: 8]

Affichage:
  -v, --verbose             Afficher chaque test
      --no-color            Désactiver les couleurs
  -h, --help                Aide
      --version             Version

Exemples:
  # Scan + extraction auto
  sqli-hunter -u "https://target.com/page?id=1" --auto-extract -v

  # Scan puis extraction (2 phases)
  sqli-hunter -u "https://target.com/product?id=1" --extract-after

  # Extraction directe (URL déjà confirmée vulnérable)
  sqli-hunter -u "https://target.com/page?id=1" --extract

  sqli-hunter -u "https://target.com/api?user=guest" -t nosql --auto-extract
  go run ./cmd/benchmark

⚠️  Utilisez uniquement sur des cibles autorisées (bug bounty, pentest contractuel).
`)
}
